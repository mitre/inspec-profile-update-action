control 'SV-203720' do
  title 'The operating system must prevent the installation of patches, service packs, device drivers, or operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.'
  desc 'Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.'
  desc 'check', 'Verify the operating system prevents the installation of patches, service packs, device drivers, or operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to prevent the installation of patches, service packs, device drivers, or operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3845r375167_chk'
  tag severity: 'medium'
  tag gid: 'V-203720'
  tag rid: 'SV-203720r379825_rule'
  tag stig_id: 'SRG-OS-000366-GPOS-00153'
  tag gtitle: 'SRG-OS-000366'
  tag fix_id: 'F-3845r375168_fix'
  tag 'documentable'
  tag legacy: ['V-56849', 'SV-71109']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
