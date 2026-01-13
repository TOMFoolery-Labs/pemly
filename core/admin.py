from django.contrib import admin

from .models import APIKey, AuditLog, Certificate, CertificateAuthority, PendingCertificateRequest


@admin.register(CertificateAuthority)
class CertificateAuthorityAdmin(admin.ModelAdmin):
    list_display = ['name', 'common_name', 'organization', 'is_active', 'not_after', 'created_at']
    list_filter = ['is_active', 'key_algorithm']
    search_fields = ['name', 'common_name', 'organization']
    readonly_fields = [
        'id', 'certificate_pem', 'private_key_pem_encrypted', 'public_key_pem',
        'serial_number', 'not_before', 'not_after', 'created_at', 'created_by'
    ]
    fieldsets = [
        ('Identity', {
            'fields': ['id', 'name', 'is_active']
        }),
        ('Subject', {
            'fields': ['common_name', 'organization', 'organizational_unit',
                      'country', 'state', 'locality']
        }),
        ('Key Configuration', {
            'fields': ['key_algorithm', 'key_size', 'validity_years']
        }),
        ('Certificate Data', {
            'fields': ['certificate_pem', 'public_key_pem', 'serial_number'],
            'classes': ['collapse']
        }),
        ('Validity', {
            'fields': ['not_before', 'not_after']
        }),
        ('Audit', {
            'fields': ['created_at', 'created_by']
        }),
    ]


@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    list_display = ['common_name', 'type', 'status', 'ca', 'not_after', 'created_at']
    list_filter = ['status', 'type', 'key_algorithm', 'ca']
    search_fields = ['common_name', 'organization', 'serial_number']
    readonly_fields = [
        'id', 'certificate_pem', 'private_key_pem_encrypted', 'public_key_pem',
        'csr_pem', 'serial_number', 'not_before', 'not_after', 'revoked_at',
        'created_at', 'created_by'
    ]
    fieldsets = [
        ('Identity', {
            'fields': ['id', 'ca', 'type', 'status']
        }),
        ('Subject', {
            'fields': ['common_name', 'organization']
        }),
        ('Subject Alternative Names', {
            'fields': ['san_dns_names', 'san_ip_addresses', 'san_email_addresses']
        }),
        ('Key Configuration', {
            'fields': ['key_algorithm', 'key_size', 'validity_days']
        }),
        ('Certificate Data', {
            'fields': ['certificate_pem', 'public_key_pem', 'csr_pem', 'serial_number'],
            'classes': ['collapse']
        }),
        ('Validity', {
            'fields': ['not_before', 'not_after']
        }),
        ('Revocation', {
            'fields': ['revoked_at', 'revocation_reason'],
            'classes': ['collapse']
        }),
        ('Audit', {
            'fields': ['created_at', 'created_by']
        }),
    ]


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'user', 'action', 'resource_type', 'resource_name', 'ip_address']
    list_filter = ['action', 'resource_type', 'timestamp']
    search_fields = ['resource_name', 'user__username', 'ip_address']
    readonly_fields = [
        'id', 'timestamp', 'user', 'action', 'resource_type', 'resource_id',
        'resource_name', 'details', 'ip_address', 'user_agent'
    ]
    date_hierarchy = 'timestamp'

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(PendingCertificateRequest)
class PendingCertificateRequestAdmin(admin.ModelAdmin):
    """Admin interface for Pending Certificate Requests."""

    list_display = ['common_name', 'requested_by', 'ca', 'status', 'requested_at', 'reviewed_by']
    list_filter = ['status', 'type', 'ca', 'requested_at']
    search_fields = ['common_name', 'organization', 'requested_by__username']
    readonly_fields = [
        'id', 'requested_by', 'requested_at', 'reviewed_by', 'reviewed_at',
        'issued_certificate', 'csr_pem'
    ]
    ordering = ['-requested_at']

    fieldsets = (
        ('Request Info', {
            'fields': ('id', 'status', 'ca', 'type')
        }),
        ('Requester', {
            'fields': ('requested_by', 'requested_at')
        }),
        ('Certificate Details', {
            'fields': ('common_name', 'organization', 'san_dns_names', 'san_ip_addresses', 'san_email_addresses')
        }),
        ('Key Configuration', {
            'fields': ('key_algorithm', 'key_size', 'validity_days')
        }),
        ('CSR', {
            'fields': ('csr_pem',),
            'classes': ('collapse',)
        }),
        ('Review', {
            'fields': ('reviewed_by', 'reviewed_at', 'rejection_reason')
        }),
        ('Result', {
            'fields': ('issued_certificate',)
        }),
    )


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    """Admin interface for API Keys."""

    list_display = ['name', 'prefix', 'user', 'is_active', 'created_at', 'last_used_at', 'expires_at']
    list_filter = ['is_active', 'created_at', 'expires_at']
    search_fields = ['name', 'prefix', 'user__username', 'user__email']
    readonly_fields = ['id', 'prefix', 'hashed_key', 'created_at', 'last_used_at']
    ordering = ['-created_at']

    fieldsets = (
        ('API Key Info', {
            'fields': ('id', 'name', 'prefix', 'hashed_key')
        }),
        ('User', {
            'fields': ('user',)
        }),
        ('Status', {
            'fields': ('is_active', 'expires_at')
        }),
        ('Usage', {
            'fields': ('created_at', 'last_used_at')
        }),
    )

    def has_add_permission(self, request):
        # API keys should be created through the API or dedicated views, not admin
        return False
