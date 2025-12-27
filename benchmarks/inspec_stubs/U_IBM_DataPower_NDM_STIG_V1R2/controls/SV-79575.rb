control 'SV-79575' do
  title 'The DataPower Gateway must prevent the installation of patches, service packs, or application components without verification the software component has been digitally signed using a certificate that is recognized and approved by the organization.'
  desc 'Changes to any software components can have significant effects on the overall security of the network device. Verifying software components have been digitally signed using a certificate that is recognized and approved by the organization ensures the software has not been tampered with and has been provided by a trusted vendor. 

Accordingly, patches, service packs, or application components must be signed with a certificate recognized and approved by the organization. 

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The device should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.'
  desc 'check', 'Login page >> Enter non-admin user ID and password, select Default for domain >> Click "Login". If non-admin user can log on, this is a finding.'
  desc 'fix', 'Privileged account user log on to default domain >> Administration >> Access >> User Account >> Select non privileged user account >> Click “…” button next to User Group field >> Enter */default/*?Access=NONE into field >> Click "Add" >> Click "Apply" >> Click "Apply" >> Click "Save Configuration".'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65711r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65085'
  tag rid: 'SV-79575r1_rule'
  tag stig_id: 'WSDP-NM-000044'
  tag gtitle: 'SRG-APP-000131-NDM-000243'
  tag fix_id: 'F-71025r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
