from django.urls import path

from . import views

app_name = 'core'

urlpatterns = [
    # Dashboard
    path('', views.DashboardView.as_view(), name='dashboard'),

    # Certificate Authority
    path('ca/setup/', views.CASetupView.as_view(), name='ca_setup'),
    path('ca/', views.CADetailView.as_view(), name='ca_detail'),
    path('ca/download/', views.CADownloadView.as_view(), name='ca_download'),

    # Certificates
    path('certificates/', views.CertificateListView.as_view(), name='certificate_list'),
    path('certificates/create/', views.CertificateCreateView.as_view(), name='certificate_create'),
    path('certificates/<uuid:pk>/', views.CertificateDetailView.as_view(), name='certificate_detail'),
    path('certificates/<uuid:pk>/revoke/', views.CertificateRevokeView.as_view(), name='certificate_revoke'),
    path('certificates/<uuid:pk>/download/<str:file_type>/', views.CertificateDownloadView.as_view(), name='certificate_download'),

    # Audit
    path('audit/', views.AuditLogView.as_view(), name='audit_log'),
]
