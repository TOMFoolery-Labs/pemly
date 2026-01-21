"""
Certificate Profile management views.
"""


from django import forms
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View
from django.views.generic import ListView

from core.models import (
    CertificateProfile,
)


class ProfileForm(forms.ModelForm):
    """Form for creating/editing certificate profiles."""

    class Meta:
        model = CertificateProfile
        fields = [
            'name',
            'description',
            'certificate_type',
            'validity_days',
            'key_algorithm',
            'key_size',
            'organization',
        ]
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add key size choices
        self.fields['key_size'] = forms.ChoiceField(
            choices=[
                (2048, 'RSA 2048-bit'),
                (4096, 'RSA 4096-bit'),
                (256, 'ECDSA P-256'),
                (384, 'ECDSA P-384'),
            ],
            initial=2048,
        )


class ProfileListView(LoginRequiredMixin, ListView):
    """List all certificate profiles."""

    model = CertificateProfile
    template_name = 'profiles/list.html'
    context_object_name = 'profiles'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['builtin_profiles'] = CertificateProfile.get_builtin_profiles()
        context['user_profiles'] = CertificateProfile.get_user_profiles()
        return context


class ProfileCreateView(LoginRequiredMixin, View):
    """Create a new certificate profile."""

    template_name = 'profiles/create.html'

    def get(self, request):
        form = ProfileForm()
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        form = ProfileForm(request.POST)

        if form.is_valid():
            profile = form.save(commit=False)
            profile.created_by = request.user
            profile.key_size = int(form.cleaned_data['key_size'])
            profile.save()

            messages.success(request, f'Profile "{profile.name}" created successfully.')
            return redirect('core:profile_list')

        return render(request, self.template_name, {'form': form})


class ProfileEditView(LoginRequiredMixin, View):
    """Edit an existing certificate profile."""

    template_name = 'profiles/edit.html'

    def get(self, request, pk):
        profile = get_object_or_404(CertificateProfile, pk=pk)

        # Prevent editing built-in profiles
        if profile.is_builtin:
            messages.error(request, 'Built-in profiles cannot be edited.')
            return redirect('core:profile_list')

        form = ProfileForm(instance=profile)
        return render(request, self.template_name, {'form': form, 'profile': profile})

    def post(self, request, pk):
        profile = get_object_or_404(CertificateProfile, pk=pk)

        if profile.is_builtin:
            messages.error(request, 'Built-in profiles cannot be edited.')
            return redirect('core:profile_list')

        form = ProfileForm(request.POST, instance=profile)

        if form.is_valid():
            profile = form.save(commit=False)
            profile.key_size = int(form.cleaned_data['key_size'])
            profile.save()

            messages.success(request, f'Profile "{profile.name}" updated successfully.')
            return redirect('core:profile_list')

        return render(request, self.template_name, {'form': form, 'profile': profile})


class ProfileDeleteView(LoginRequiredMixin, View):
    """Delete a certificate profile."""

    template_name = 'profiles/delete.html'

    def get(self, request, pk):
        profile = get_object_or_404(CertificateProfile, pk=pk)

        if profile.is_builtin:
            messages.error(request, 'Built-in profiles cannot be deleted.')
            return redirect('core:profile_list')

        return render(request, self.template_name, {'profile': profile})

    def post(self, request, pk):
        profile = get_object_or_404(CertificateProfile, pk=pk)

        if profile.is_builtin:
            messages.error(request, 'Built-in profiles cannot be deleted.')
            return redirect('core:profile_list')

        name = profile.name
        profile.delete()

        messages.success(request, f'Profile "{name}" deleted.')
        return redirect('core:profile_list')


class ProfileDataView(LoginRequiredMixin, View):
    """API endpoint to get profile data for form auto-fill."""

    def get(self, request, pk):
        profile = get_object_or_404(CertificateProfile, pk=pk)

        return JsonResponse({
            'id': str(profile.id),
            'name': profile.name,
            'certificate_type': profile.certificate_type,
            'validity_days': profile.validity_days,
            'key_algorithm': profile.key_algorithm,
            'key_size': profile.key_size,
            'organization': profile.organization,
        })
