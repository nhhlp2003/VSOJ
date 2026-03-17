import csv
import io
import re
import secrets
import string

from django.conf import settings
from django.contrib import admin, messages
from django.contrib.auth.admin import UserAdmin as OldUserAdmin
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import IntegrityError
from django.forms import ModelForm
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.urls import path, reverse, reverse_lazy
from django.utils.html import format_html
from django.utils.translation import gettext, gettext_lazy as _, ngettext
from reversion.admin import VersionAdmin

from django_ace import AceWidget
from judge.models import Language, Organization, Profile, WebAuthnCredential
from judge.utils.views import NoBatchDeleteMixin
from judge.widgets import AdminMartorWidget, AdminSelect2MultipleWidget, AdminSelect2Widget

BATCH_PASSWORD_ALPHABET = string.ascii_letters + string.digits
USERNAME_REGEX = re.compile(r'^\w+$', re.ASCII)
USERNAME_MAX_LENGTH = 30
FULLNAME_MAX_LENGTH = 30

_bad_mail_regex_cache = None


def _get_bad_mail_regex():
    global _bad_mail_regex_cache
    if _bad_mail_regex_cache is None:
        _bad_mail_regex_cache = list(map(re.compile, settings.BAD_MAIL_PROVIDER_REGEX))
    return _bad_mail_regex_cache


def _validate_email_policy(email):
    """Validate email against system policies (format, uniqueness, bad providers)."""
    errors = []
    if not email:
        return errors  # email is optional
    try:
        validate_email(email)
    except ValidationError:
        errors.append('invalid email format')
        return errors
    if User.objects.filter(email=email).exists():
        errors.append('email already in use')
    domain = email.split('@')[-1].lower()
    if domain in settings.BAD_MAIL_PROVIDERS or any(r.match(domain) for r in _get_bad_mail_regex()):
        errors.append('email provider not allowed')
    return errors


def _validate_username(username):
    """Validate username against system policies (regex, length, uniqueness)."""
    errors = []
    if not username:
        errors.append('empty username')
        return errors
    if len(username) > USERNAME_MAX_LENGTH:
        errors.append('username too long (max %d chars)' % USERNAME_MAX_LENGTH)
    if not USERNAME_REGEX.match(username):
        errors.append('username must contain only letters, numbers, or underscores')
    if User.objects.filter(username=username).exists():
        errors.append('username already exists')
    return errors


def generate_password():
    return ''.join(secrets.choice(BATCH_PASSWORD_ALPHABET) for _ in range(8))


class ProfileForm(ModelForm):
    def __init__(self, *args, **kwargs):
        super(ProfileForm, self).__init__(*args, **kwargs)
        self.fields['display_badge'].queryset = self.instance.badges.all()
        self.fields['display_badge'].required = False
        if 'current_contest' in self.base_fields:
            # form.fields['current_contest'] does not exist when the user has only view permission on the model.
            self.fields['current_contest'].queryset = self.instance.contest_history.select_related('contest') \
                .only('contest__name', 'user_id', 'virtual')
            self.fields['current_contest'].label_from_instance = \
                lambda obj: '%s v%d' % (obj.contest.name, obj.virtual) if obj.virtual else obj.contest.name

    class Meta:
        widgets = {
            'timezone': AdminSelect2Widget,
            'language': AdminSelect2Widget,
            'ace_theme': AdminSelect2Widget,
            'current_contest': AdminSelect2Widget,
            'badges': AdminSelect2MultipleWidget(attrs={'style': 'width: 100%'}),
            'display_badge': AdminSelect2Widget,
            'about': AdminMartorWidget(attrs={'data-markdownfy-url': reverse_lazy('profile_preview')}),
        }


class TimezoneFilter(admin.SimpleListFilter):
    title = _('timezone')
    parameter_name = 'timezone'

    def lookups(self, request, model_admin):
        return Profile.objects.values_list('timezone', 'timezone').distinct().order_by('timezone')

    def queryset(self, request, queryset):
        if self.value() is None:
            return queryset
        return queryset.filter(timezone=self.value())


class WebAuthnInline(admin.TabularInline):
    model = WebAuthnCredential
    readonly_fields = ('cred_id', 'public_key', 'counter')
    extra = 0

    def has_add_permission(self, request, obj=None):
        return False


class ProfileAdmin(NoBatchDeleteMixin, VersionAdmin):
    fields = ('user', 'display_rank', 'badges', 'display_badge', 'about', 'organizations', 'vnoj_points', 'timezone',
              'language', 'ace_theme', 'math_engine', 'last_access', 'ip', 'mute', 'is_unlisted', 'allow_tagging',
              'notes', 'username_display_override', 'ban_reason', 'is_totp_enabled', 'ip_auth', 'user_script',
              'current_contest')
    readonly_fields = ('user',)
    list_display = ('admin_user_admin', 'email', 'is_totp_enabled', 'timezone_full',
                    'date_joined', 'last_access', 'ip', 'show_public')
    ordering = ('user__username',)
    search_fields = ('user__username', 'ip', 'user__email')
    list_filter = ('language', TimezoneFilter)
    actions = ('recalculate_points', 'recalulate_contribution_points')
    actions_on_top = True
    actions_on_bottom = True
    form = ProfileForm
    inlines = [WebAuthnInline]

    def has_add_permission(self, request, obj=None):
        return False

    # We can't use has_delete_permission here because we still want user profiles to be
    # deleteable through related objects (i.e. User). Thus, we simply hide the delete button.
    # If an admin wants to go directly to the delete endpoint to delete a profile, more
    # power to them.
    def render_change_form(self, request, context, **kwargs):
        context['show_delete'] = False
        return super().render_change_form(request, context, **kwargs)

    def get_queryset(self, request):
        return super(ProfileAdmin, self).get_queryset(request).select_related('user')

    def get_fields(self, request, obj=None):
        if request.user.has_perm('judge.totp'):
            fields = list(self.fields)
            fields.insert(fields.index('is_totp_enabled') + 1, 'totp_key')
            fields.insert(fields.index('totp_key') + 1, 'scratch_codes')
            return tuple(fields)
        else:
            return self.fields

    def get_readonly_fields(self, request, obj=None):
        fields = self.readonly_fields
        if not request.user.has_perm('judge.totp'):
            fields += ('is_totp_enabled',)
        return fields

    @admin.display(description='')
    def show_public(self, obj):
        return format_html('<a href="{0}" style="white-space:nowrap;">{1}</a>',
                           obj.get_absolute_url(), gettext('View on site'))

    @admin.display(description=_('user'), ordering='user__username')
    def admin_user_admin(self, obj):
        return obj.username

    @admin.display(description=_('email'), ordering='user__email')
    def email(self, obj):
        return obj.user.email

    @admin.display(description=_('timezone'), ordering='timezone')
    def timezone_full(self, obj):
        return obj.timezone

    @admin.display(description=_('date joined'), ordering='user__date_joined')
    def date_joined(self, obj):
        return obj.user.date_joined

    @admin.display(description=_('Recalculate scores'))
    def recalculate_points(self, request, queryset):
        count = 0
        for profile in queryset:
            profile.calculate_points()
            count += 1
        self.message_user(request, ngettext('%d user had scores recalculated.',
                                            '%d users had scores recalculated.',
                                            count) % count)

    @admin.display(description=_('Recalulate contribution points'))
    def recalulate_contribution_points(self, request, queryset):
        count = 0
        for profile in queryset:
            profile.calculate_contribution_points()
            count += 1
        self.message_user(request, ngettext('%d user has contribution scores recalculated.',
                                            '%d users have contribution scores recalculated.',
                                            count) % count)

    def get_form(self, request, obj=None, **kwargs):
        form = super(ProfileAdmin, self).get_form(request, obj, **kwargs)
        if 'user_script' in form.base_fields:
            # form.base_fields['user_script'] does not exist when the user has only view permission on the model.
            form.base_fields['user_script'].widget = AceWidget(
                mode='javascript', theme=request.profile.resolved_ace_theme,
            )
        return form

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if form.changed_data and 'ban_reason' in form.changed_data and form.cleaned_data['ban_reason'] == '':
            obj.ban_reason = None
            obj.save()


class UserAdmin(OldUserAdmin):
    change_list_template = 'admin/auth/user/change_list.html'

    def get_urls(self):
        custom_urls = [
            path('batch-add/', self.admin_site.admin_view(self.batch_add_view), name='auth_user_batch_add'),
            path('batch-add/template/', self.admin_site.admin_view(self.download_template_view),
                 name='auth_user_batch_template'),
            path('batch-add/process/', self.admin_site.admin_view(self.process_batch_view),
                 name='auth_user_batch_process'),
        ]
        return custom_urls + super().get_urls()

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if not change:
            Profile.objects.create(user=obj)

    def batch_add_view(self, request):
        context = {
            **self.admin_site.each_context(request),
            'title': _('Batch Add Users'),
            'opts': self.model._meta,
            'template_url': reverse('admin:auth_user_batch_template'),
            'process_url': reverse('admin:auth_user_batch_process'),
        }
        return render(request, 'admin/auth/user/batch_add.html', context)

    def download_template_view(self, request):
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="batch_users_template.csv"'
        writer = csv.writer(response)
        writer.writerow(['username', 'fullname', 'email', 'organization'])
        writer.writerow(['example_user', 'Example User', 'user@example.com', 'org-slug'])
        return response

    def _error_response(self, request, msg):
        """Return JSON error for AJAX, or redirect with message for normal requests."""
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'error': str(msg)}, status=400)
        messages.error(request, msg)
        return redirect(reverse('admin:auth_user_batch_add'))

    def process_batch_view(self, request):
        if request.method != 'POST':
            return redirect(reverse('admin:auth_user_batch_add'))

        csv_file = request.FILES.get('csv_file')
        if not csv_file:
            return self._error_response(request, _('No CSV file was uploaded.'))

        if not csv_file.name.endswith('.csv'):
            return self._error_response(request, _('Please upload a valid CSV file.'))

        try:
            decoded_file = csv_file.read().decode('utf-8-sig')
        except UnicodeDecodeError:
            return self._error_response(request, _('Could not decode the CSV file. Please ensure it is UTF-8 encoded.'))

        reader = csv.DictReader(io.StringIO(decoded_file))

        if not reader.fieldnames or 'username' not in reader.fieldnames:
            return self._error_response(request, _('CSV file must have a "username" column.'))

        result_rows = []
        created_count = 0
        skipped_count = 0
        error_count = 0
        default_language = Language.objects.get(key=settings.DEFAULT_USER_LANGUAGE)

        # Global password: if provided, validate against Django's password validators
        global_password = request.POST.get('global_password', '').strip()
        if global_password:
            try:
                validate_password(global_password)
            except ValidationError as e:
                return self._error_response(request, _('Password does not meet requirements: %s') %
                                            '; '.join(e.messages))

        for i, row in enumerate(reader, start=2):
            username = row.get('username', '').strip()
            fullname = row.get('fullname', '').strip()
            email = row.get('email', '').strip()
            org_slug = row.get('organization', '').strip()

            # --- Validation phase ---
            validation_errors = []

            # Username validation
            validation_errors.extend(_validate_username(username))

            # Fullname validation
            if fullname and len(fullname) > FULLNAME_MAX_LENGTH:
                validation_errors.append('fullname too long (max %d chars)' % FULLNAME_MAX_LENGTH)

            # Email validation
            validation_errors.extend(_validate_email_policy(email))

            # Organization validation (pre-check)
            org = None
            if org_slug:
                try:
                    org = Organization.objects.get(slug=org_slug)
                    if org.slots is not None and org.member_count >= org.slots:
                        validation_errors.append('organization "%s" is full (%d/%d)' %
                                                 (org_slug, org.member_count, org.slots))
                except Organization.DoesNotExist:
                    validation_errors.append('organization "%s" not found' % org_slug)

            # If any validation error, skip this row
            if validation_errors:
                status_msg = 'skipped: ' + '; '.join(validation_errors)
                result_rows.append({
                    'username': username, 'fullname': fullname, 'email': email,
                    'organization': org_slug, 'password': '',
                    'status': status_msg,
                })
                skipped_count += 1
                continue

            # --- Creation phase ---
            password = global_password if global_password else generate_password()
            try:
                user = User(username=username, first_name=fullname, email=email, is_active=True)
                user.set_password(password)
                user.full_clean()
                user.save()

                profile = Profile(user=user, language=default_language)
                profile.save()

                if org:
                    profile.organizations.add(org)
                    org.on_user_changes()

                created_count += 1
                result_rows.append({
                    'username': username, 'fullname': fullname, 'email': email,
                    'organization': org_slug, 'password': password,
                    'status': 'created',
                })
            except ValidationError as e:
                error_count += 1
                error_msgs = '; '.join(
                    msg for msg_list in e.message_dict.values() for msg in msg_list
                ) if hasattr(e, 'message_dict') else str(e)
                result_rows.append({
                    'username': username, 'fullname': fullname, 'email': email,
                    'organization': org_slug, 'password': '',
                    'status': 'error: %s' % error_msgs,
                })
            except IntegrityError as e:
                error_count += 1
                result_rows.append({
                    'username': username, 'fullname': fullname, 'email': email,
                    'organization': org_slug, 'password': '',
                    'status': 'error: %s' % str(e),
                })
            except Exception as e:
                error_count += 1
                result_rows.append({
                    'username': username, 'fullname': fullname, 'email': email,
                    'organization': org_slug, 'password': '',
                    'status': 'error: %s' % str(e),
                })

        if not result_rows:
            return self._error_response(request, _('The CSV file contained no data rows.'))

        # Return the result CSV with ALL rows (created, skipped, errored)
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="batch_result.csv"'
        fieldnames = ['username', 'fullname', 'email', 'organization', 'password', 'status']
        writer = csv.DictWriter(response, fieldnames=fieldnames)
        writer.writeheader()
        for row_data in result_rows:
            writer.writerow(row_data)

        # Flash messages summary
        summary_parts = []
        if created_count:
            summary_parts.append(_('%d created') % created_count)
        if skipped_count:
            summary_parts.append(_('%d skipped') % skipped_count)
        if error_count:
            summary_parts.append(_('%d errors') % error_count)
        messages.info(request, _('Batch result: %s. Check the downloaded CSV for details.') %
                      ', '.join(summary_parts))

        return response
