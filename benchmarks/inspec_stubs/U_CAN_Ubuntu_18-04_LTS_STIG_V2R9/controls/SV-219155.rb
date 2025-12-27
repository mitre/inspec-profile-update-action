control 'SV-219155' do
  title 'Advance package Tool (APT) must be configured to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.'
  desc 'Changes to any software components can have significant effects on the overall security of the Ubuntu operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Accordingly, patches, service packs, device drivers, or Ubuntu operating system components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The Ubuntu operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.'
  desc 'check', 'Verify that Advance package Tool (APT) is configured to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.

Check that the "AllowUnauthenticated" variable is not set at all or set to "false" with the following command:

# grep AllowUnauthenticated /etc/apt/apt.conf.d/*
/etc/apt/apt.conf.d/01-vendor-Ubuntu:APT::Get::AllowUnauthenticated "false";

If any of the files returned from the command with "AllowUnauthenticated" set to "true", this is a finding.'
  desc 'fix', 'Configure Advance package Tool (APT) to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.

Remove/Update any APT configuration file that contain the variable "AllowUnauthenticated" to "false", or remove "AllowUnauthenticated" entirely from each file. Below is an example of setting the "AllowUnauthenticated" variable to "false":

APT::Get::AllowUnauthenticated "false";'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20880r304793_chk'
  tag severity: 'medium'
  tag gid: 'V-219155'
  tag rid: 'SV-219155r853363_rule'
  tag stig_id: 'UBTU-18-010016'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-20879r304794_fix'
  tag 'documentable'
  tag legacy: ['SV-109639', 'V-100535']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
