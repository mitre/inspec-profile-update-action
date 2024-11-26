control 'SV-204740' do
  title 'The application server must prevent the installation of patches, service packs, or application components without verification the software component has been digitally signed using a certificate that is recognized and approved by the organization.'
  desc 'Changes to any software components can have significant effects on the overall security of the application. Verifying software components have been digitally signed using a certificate that is recognized and approved by the organization ensures the software has not been tampered with and that it has been provided by a trusted vendor. 

Accordingly, patches, service packs, or application components must be signed with a certificate recognized and approved by the organization. 

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The application should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.'
  desc 'check', 'Review system documentation to determine if the application server prevents the installation of patches, service packs, or application components without verification the software component has been digitally signed using a certificate that is recognized and approved by the organization.

If the application server does not meet this requirement, this is a finding.'
  desc 'fix', 'Configure the application server to prevent the installation of patches, service packs, or application components without verification the software component has been digitally signed using a certificate that is recognized and approved by the organization.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4860r282867_chk'
  tag severity: 'medium'
  tag gid: 'V-204740'
  tag rid: 'SV-204740r508029_rule'
  tag stig_id: 'SRG-APP-000131-AS-000002'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-4860r282868_fix'
  tag 'documentable'
  tag legacy: ['V-57495', 'SV-71771']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
