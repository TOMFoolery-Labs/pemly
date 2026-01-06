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

    # Legacy CRL endpoint (backwards compatibility)
    path('crl/', views.CRLView.as_view(), name='crl_legacy'),

    # Certificates
    path('certificates/', views.CertificateListView.as_view(), name='certificate_list'),
    path('certificates/create/', views.CertificateCreateView.as_view(), name='certificate_create'),
    path('certificates/<uuid:pk>/', views.CertificateDetailView.as_view(), name='certificate_detail'),
    path('certificates/<uuid:pk>/revoke/', views.CertificateRevokeView.as_view(), name='certificate_revoke'),
    path('certificates/<uuid:pk>/download/<str:file_type>/', views.CertificateDownloadView.as_view(), name='certificate_download'),

    # API endpoints
    path('api/parse-csr/', views.CSRParseView.as_view(), name='api_parse_csr'),

    # Audit
    path('audit/', views.AuditLogView.as_view(), name='audit_log'),

    # Settings
    path('settings/', views.SettingsView.as_view(), name='settings'),
    path('settings/cfssl/', views.CFSSLActionView.as_view(), name='cfssl_action'),
]
