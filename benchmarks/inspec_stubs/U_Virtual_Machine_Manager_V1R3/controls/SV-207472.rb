control 'SV-207472' do
  title 'The VMM must prevent the installation of guest VMs, patches, service packs, device drivers, or VMM components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.'
  desc 'Changes to any software components can have significant effects on the overall security of the VMM. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor. 

Accordingly, guest VMs, patches, service packs, device drivers, or VMM components must be signed with a certificate recognized and approved by the organization. 

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The VMM should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.'
  desc 'check', 'Verify the VMM prevents the installation of guest VMs, patches, service packs, device drivers, or VMM components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to prevent the installation of guest VMs, patches, service packs, device drivers, or VMM components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7729r878137_chk'
  tag severity: 'medium'
  tag gid: 'V-207472'
  tag rid: 'SV-207472r878138_rule'
  tag stig_id: 'SRG-OS-000366-VMM-001430'
  tag gtitle: 'SRG-OS-000366'
  tag fix_id: 'F-7729r365821_fix'
  tag 'documentable'
  tag legacy: ['V-57145', 'SV-71405']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
