from django.urls import path

from . import views

app_name = 'core'

urlpatterns = [
    # Dashboard
    path('', views.DashboardView.as_view(), name='dashboard'),

    # Certificate Authority - List and Setup
    path('ca/', views.CAListView.as_view(), name='ca_list'),
    path('ca/setup/', views.CASetupView.as_view(), name='ca_setup'),

    # Certificate Authority - Individual CA operations
    path('ca/<uuid:pk>/', views.CADetailView.as_view(), name='ca_detail'),
    path('ca/<uuid:pk>/download/', views.CADownloadView.as_view(), name='ca_download'),
    path('ca/<uuid:pk>/crl/', views.CRLView.as_view(), name='ca_crl'),

    # Intermediate CA creation
    path('ca/<uuid:pk>/create-intermediate/', views.IntermediateCACreateView.as_view(), name='intermediate_create'),
    path('ca/<uuid:pk>/create-intermediate-csr/', views.IntermediateCACSRView.as_view(), name='intermediate_create_csr'),
    path('ca/<uuid:pk>/import-certificate/', views.IntermediateCAImportView.as_view(), name='intermediate_import_cert'),

    # Air-gap operations
    path('ca/<uuid:pk>/export-key/', views.CAKeyExportView.as_view(), name='ca_export_key'),
    path('ca/<uuid:pk>/remove-key/', views.CAKeyRemoveView.as_view(), name='ca_remove_key'),
    path('ca/<uuid:pk>/restore-key/', views.CAKeyRestoreView.as_view(), name='ca_restore_key'),

    # OCSP Configuration
    path('ca/<uuid:pk>/ocsp/', views.OCSPConfigView.as_view(), name='ca_ocsp_config'),
    path('ca/<uuid:pk>/ocsp/generate/', views.OCSPGenerateCertView.as_view(), name='ca_ocsp_generate'),

    # Legacy CRL endpoint (backwards compatibility)
    path('crl/', views.CRLView.as_view(), name='crl_legacy'),

    # Certificates
    path('certificates/', views.CertificateListView.as_view(), name='certificate_list'),
    path('certificates/create/', views.CertificateCreateView.as_view(), name='certificate_create'),
    path('certificates/request/', views.CertificateRequestCreateView.as_view(), name='certificate_request'),
    path('certificates/<uuid:pk>/', views.CertificateDetailView.as_view(), name='certificate_detail'),
    path('certificates/<uuid:pk>/revoke/', views.CertificateRevokeView.as_view(), name='certificate_revoke'),
    path('certificates/<uuid:pk>/renew/', views.CertificateRenewView.as_view(), name='certificate_renew'),
    path('certificates/<uuid:pk>/archive/', views.CertificateArchiveView.as_view(), name='certificate_archive'),
    path('certificates/<uuid:pk>/unarchive/', views.CertificateUnarchiveView.as_view(), name='certificate_unarchive'),
    path('certificates/<uuid:pk>/download/<str:file_type>/', views.CertificateDownloadView.as_view(), name='certificate_download'),

    # Certificate Request Approval Workflow
    path('approvals/', views.PendingRequestListView.as_view(), name='approval_list'),
    path('approvals/<uuid:pk>/', views.PendingRequestDetailView.as_view(), name='pending_request_detail'),
    path('approvals/<uuid:pk>/approve/', views.PendingRequestApproveView.as_view(), name='pending_request_approve'),
    path('approvals/<uuid:pk>/reject/', views.PendingRequestRejectView.as_view(), name='pending_request_reject'),

    # API endpoints
    path('api/parse-csr/', views.CSRParseView.as_view(), name='api_parse_csr'),
    path('api/profiles/<uuid:pk>/', views.ProfileDataView.as_view(), name='api_profile_data'),

    # Certificate Profiles
    path('profiles/', views.ProfileListView.as_view(), name='profile_list'),
    path('profiles/create/', views.ProfileCreateView.as_view(), name='profile_create'),
    path('profiles/<uuid:pk>/edit/', views.ProfileEditView.as_view(), name='profile_edit'),
    path('profiles/<uuid:pk>/delete/', views.ProfileDeleteView.as_view(), name='profile_delete'),

    # Audit
    path('audit/', views.AuditLogView.as_view(), name='audit_log'),

    # Settings
    path('settings/', views.SettingsView.as_view(), name='settings'),
    path('settings/cfssl/', views.CFSSLActionView.as_view(), name='cfssl_action'),
    path('settings/test-email/', views.SendTestEmailView.as_view(), name='send_test_email'),

    # Backup & Restore
    path('settings/backup/', views.BackupView.as_view(), name='backup'),
    path('settings/restore/upload/', views.RestoreUploadView.as_view(), name='restore_upload'),
    path('settings/restore/confirm/', views.RestoreConfirmView.as_view(), name='restore_confirm'),

    # API Keys
    path('api-keys/', views.APIKeyListView.as_view(), name='api_key_list'),
    path('api-keys/create/', views.APIKeyCreateView.as_view(), name='api_key_create'),
    path('api-keys/<uuid:pk>/delete/', views.APIKeyDeleteView.as_view(), name='api_key_delete'),

    # OCSP Responder (public, no auth required)
    path('ocsp/<uuid:ca_id>/', views.OCSPResponderView.as_view(), name='ocsp_responder'),
    path('ocsp/<uuid:ca_id>/<path:ocsp_request>', views.OCSPResponderGetView.as_view(), name='ocsp_responder_get'),
]
