"""
Views for certificate request approval workflow.

Certificate Requesters submit CSRs that must be approved by Certificate Managers,
Administrators, or Super Admins before being issued as certificates.
"""

import logging

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views import View
from django.views.generic import ListView, DetailView

from core.forms import CertificateRequestForm, RejectRequestForm
from core.models import PendingCertificateRequest, Certificate, AuditLog
from core.permissions import CanManageCertificatesMixin, get_pending_requests_for_user
from core.cfssl import issue_certificate_from_csr
from accounts.models import UserProfile


def get_client_ip(request):
    """Extract client IP from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')


class CertificateRequestCreateView(LoginRequiredMixin, View):
    """
    Certificate Requesters submit CSR for approval.

    GET: Show the CSR submission form
    POST: Create a pending certificate request
    """

    def get(self, request):
        form = CertificateRequestForm()
        return render(request, 'approvals/request_create.html', {
            'form': form,
        })

    def post(self, request):
        form = CertificateRequestForm(request.POST)

        if form.is_valid():
            # Create the pending request
            pending_request = form.save(
                commit=True,
                requested_by=request.user
            )

            # Audit log
            AuditLog.log(
                action=AuditLog.Action.CERT_REQUEST_SUBMITTED,
                resource_type='certificate_request',
                resource_id=str(pending_request.id),
                resource_name=pending_request.common_name,
                user=request.user,
                details={
                    'common_name': pending_request.common_name,
                    'type': pending_request.get_type_display(),
                    'ca': pending_request.ca.name,
                    'san_dns_names': pending_request.san_dns_names,
                },
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

            # Send notification to managers
            try:
                from core.services.email import send_bulk_notification
                from accounts.models import UserProfile
                from django.contrib.auth.models import User

                # Get all managers who can approve requests
                manager_users = User.objects.filter(
                    profile__role__in=[
                        UserProfile.Role.SUPER_ADMIN,
                        UserProfile.Role.ADMINISTRATOR,
                        UserProfile.Role.CERTIFICATE_MANAGER
                    ]
                )

                send_bulk_notification(
                    users=list(manager_users),
                    notification_type='request_submitted',
                    context={
                        'subject': f'New Certificate Request: {pending_request.common_name}',
                        'requester': request.user,
                        'request': pending_request,
                        'request_url': request.build_absolute_uri(
                            reverse('core:pending_request_detail', args=[pending_request.pk])
                        ),
                    }
                )
            except Exception as e:
                # Don't fail the request if email fails
                logger = logging.getLogger(__name__)
                logger.error(f"Failed to send request submitted notification: {e}")

            messages.success(
                request,
                f"Certificate request for '{pending_request.common_name}' submitted successfully. "
                "It will be reviewed by a Certificate Manager."
            )
            return redirect('core:pending_request_detail', pk=pending_request.pk)

        return render(request, 'approvals/request_create.html', {
            'form': form,
        })


class PendingRequestListView(LoginRequiredMixin, ListView):
    """
    List pending certificate requests.

    - Certificate Requesters: See only their own requests
    - Managers/Admins: See all pending requests for approval
    """

    model = PendingCertificateRequest
    template_name = 'approvals/list.html'
    context_object_name = 'requests'
    paginate_by = 25

    def get_queryset(self):
        """Filter requests based on user role."""
        user = self.request.user

        # Get requests visible to this user
        queryset = get_pending_requests_for_user(user).select_related(
            'ca', 'requested_by', 'reviewed_by', 'issued_certificate'
        )

        # Filter by status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)
        else:
            # Default to showing only pending for managers
            if user.profile.role in ['super_admin', 'administrator', 'certificate_manager']:
                queryset = queryset.filter(status=PendingCertificateRequest.Status.PENDING)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['statuses'] = PendingCertificateRequest.Status.choices
        context['current_status'] = self.request.GET.get('status', '')

        # Count pending requests for managers
        if self.request.user.profile.role in ['super_admin', 'administrator', 'certificate_manager']:
            context['pending_count'] = PendingCertificateRequest.objects.filter(
                status=PendingCertificateRequest.Status.PENDING
            ).count()

        return context


class PendingRequestDetailView(LoginRequiredMixin, DetailView):
    """
    View details of a pending certificate request.

    - Requesters can view their own requests
    - Managers can view all requests
    """

    model = PendingCertificateRequest
    template_name = 'approvals/detail.html'
    context_object_name = 'request_obj'

    def get_queryset(self):
        """Ensure user can only see requests they have access to."""
        return get_pending_requests_for_user(self.request.user).select_related(
            'ca', 'requested_by', 'reviewed_by', 'issued_certificate'
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        request_obj = self.get_object()

        # Check if current user can approve/reject
        user = self.request.user
        can_approve = (
            user.profile.role in ['super_admin', 'administrator', 'certificate_manager'] and
            request_obj.status == PendingCertificateRequest.Status.PENDING and
            request_obj.requested_by != user  # Can't approve own request
        )
        context['can_approve'] = can_approve

        # Rejection form
        if can_approve:
            context['reject_form'] = RejectRequestForm()

        return context


class PendingRequestApproveView(CanManageCertificatesMixin, View):
    """
    Approve a certificate request and issue the certificate.

    Only Certificate Managers, Administrators, and Super Admins can approve.
    Users cannot approve their own requests.
    """

    @transaction.atomic
    def post(self, request, pk):
        pending_request = get_object_or_404(
            PendingCertificateRequest.objects.select_for_update(),
            pk=pk
        )

        # Verify status is still pending
        if pending_request.status != PendingCertificateRequest.Status.PENDING:
            messages.error(
                request,
                f"This request has already been {pending_request.get_status_display().lower()}."
            )
            return redirect('core:pending_request_detail', pk=pk)

        # Prevent approving own requests
        if pending_request.requested_by == request.user:
            raise PermissionDenied("You cannot approve your own certificate request.")

        try:
            # Issue the certificate using CFSSL
            cert_data = issue_certificate_from_csr(
                ca=pending_request.ca,
                csr_pem=pending_request.csr_pem,
                cert_type=pending_request.type,
                validity_days=pending_request.validity_days
            )

            # Create the Certificate object
            certificate = Certificate.objects.create(
                ca=pending_request.ca,
                common_name=pending_request.common_name,
                organization=pending_request.organization or pending_request.ca.organization,
                type=pending_request.type,
                key_algorithm=pending_request.key_algorithm,
                key_size=pending_request.key_size,
                san_dns_names=pending_request.san_dns_names,
                san_ip_addresses=pending_request.san_ip_addresses,
                san_email_addresses=pending_request.san_email_addresses,
                certificate_pem=cert_data['certificate'],
                serial_number=cert_data['serial_number'],
                not_before=cert_data['not_before'],
                not_after=cert_data['not_after'],
                # No private_key_pem_encrypted - CSR-based, so has_private_key will be False
                created_by=pending_request.requested_by,  # Original requester
            )

            # Update pending request
            pending_request.status = PendingCertificateRequest.Status.ISSUED
            pending_request.reviewed_by = request.user
            pending_request.reviewed_at = timezone.now()
            pending_request.issued_certificate = certificate
            pending_request.save()

            # Audit log for approval
            AuditLog.log(
                action=AuditLog.Action.CERT_REQUEST_APPROVED,
                resource_type='certificate_request',
                resource_id=str(pending_request.id),
                resource_name=pending_request.common_name,
                user=request.user,
                details={
                    'requester': pending_request.requested_by.username,
                    'common_name': certificate.common_name,
                    'serial_number': certificate.serial_number,
                    'issued_certificate_id': str(certificate.id),
                },
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

            # Audit log for certificate issuance
            AuditLog.log(
                action=AuditLog.Action.CERT_ISSUED,
                resource_type='certificate',
                resource_id=str(certificate.id),
                resource_name=certificate.common_name,
                user=request.user,
                details={
                    'serial_number': certificate.serial_number,
                    'type': certificate.get_type_display(),
                    'ca': certificate.ca.name,
                    'requester': pending_request.requested_by.username,
                    'via_approval': True,
                },
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

            # Send notification to requester
            try:
                from core.services.email import send_notification

                send_notification(
                    to_user=pending_request.requested_by,
                    notification_type='request_approved',
                    context={
                        'subject': f'Certificate Request Approved: {certificate.common_name}',
                        'request': pending_request,
                        'certificate': certificate,
                        'approver': request.user,
                        'certificate_url': request.build_absolute_uri(
                            reverse('core:certificate_detail', args=[certificate.pk])
                        ),
                    }
                )
            except Exception as e:
                logger = logging.getLogger(__name__)
                logger.error(f"Failed to send request approved notification: {e}")

            messages.success(
                request,
                f"Certificate request approved and certificate issued successfully. "
                f"Serial: {certificate.serial_number}"
            )
            return redirect('core:certificate_detail', pk=certificate.pk)

        except Exception as e:
            messages.error(
                request,
                f"Failed to issue certificate: {str(e)}"
            )
            return redirect('core:pending_request_detail', pk=pk)


class PendingRequestRejectView(CanManageCertificatesMixin, View):
    """
    Reject a certificate request with a reason.

    Only Certificate Managers, Administrators, and Super Admins can reject.
    Users cannot reject their own requests.
    """

    @transaction.atomic
    def post(self, request, pk):
        pending_request = get_object_or_404(
            PendingCertificateRequest.objects.select_for_update(),
            pk=pk
        )

        # Verify status is still pending
        if pending_request.status != PendingCertificateRequest.Status.PENDING:
            messages.error(
                request,
                f"This request has already been {pending_request.get_status_display().lower()}."
            )
            return redirect('core:pending_request_detail', pk=pk)

        # Prevent rejecting own requests
        if pending_request.requested_by == request.user:
            raise PermissionDenied("You cannot reject your own certificate request.")

        form = RejectRequestForm(request.POST)
        if not form.is_valid():
            messages.error(request, "Please provide a rejection reason.")
            return redirect('core:pending_request_detail', pk=pk)

        # Update pending request
        pending_request.status = PendingCertificateRequest.Status.REJECTED
        pending_request.reviewed_by = request.user
        pending_request.reviewed_at = timezone.now()
        pending_request.rejection_reason = form.cleaned_data['rejection_reason']
        pending_request.save()

        # Audit log
        AuditLog.log(
            action=AuditLog.Action.CERT_REQUEST_REJECTED,
            resource_type='certificate_request',
            resource_id=str(pending_request.id),
            resource_name=pending_request.common_name,
            user=request.user,
            details={
                'requester': pending_request.requested_by.username,
                'common_name': pending_request.common_name,
                'rejection_reason': pending_request.rejection_reason,
            },
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )

        # Send notification to requester
        try:
            from core.services.email import send_notification

            send_notification(
                to_user=pending_request.requested_by,
                notification_type='request_rejected',
                context={
                    'subject': f'Certificate Request Rejected: {pending_request.common_name}',
                    'request': pending_request,
                    'rejector': request.user,
                    'rejection_reason': pending_request.rejection_reason,
                }
            )
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to send request rejected notification: {e}")

        messages.success(
            request,
            f"Certificate request for '{pending_request.common_name}' has been rejected."
        )
        return redirect('core:approval_list')
