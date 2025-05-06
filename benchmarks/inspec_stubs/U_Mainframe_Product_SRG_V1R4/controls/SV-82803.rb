control 'SV-82803' do
  title 'The Mainframe Product must prevent the installation of patches, service packs, or application components without verification that the software component has been digitally signed using a certificate that is recognized and approved by the organization.'
  desc 'Changes to any software components can have significant effects on the overall security of the application. Verifying software components have been digitally signed using a certificate that is recognized and approved by the organization ensures the software has not been tampered with and that it has been provided by a trusted vendor. 

Accordingly, patches, service packs, or application components must be signed with a certificate recognized and approved by the organization. 

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The application should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.'
  desc 'check', 'Examine installation and configuration settings for change management.

If the Mainframe Product does not prevent the installation of patches, service packs, or application components without verification that the software component has been digitally signed using a certificate that is recognized and approved by the organization, this is a finding.'
  desc 'fix', 'Configure installation and configuration settings for change management to prevent the installation of patches, service packs, or application components without verification that the software component has been digitally signed using a certificate that is recognized and approved by the organization.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68873r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68313'
  tag rid: 'SV-82803r1_rule'
  tag stig_id: 'SRG-APP-000131-MFP-000189'
  tag gtitle: 'SRG-APP-000131-MFP-000189'
  tag fix_id: 'F-74427r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
