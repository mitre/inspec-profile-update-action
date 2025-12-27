control 'SV-100861' do
  title 'Patches, service packs, and upgrades to the vAMI must be verifiably signed using a digital certificate that is recognized and approved by the organization.'
  desc 'Changes to any software components can have significant effects on the overall security of the application. Verifying software components have been digitally signed using a certificate that is recognized and approved by the organization ensures the software has not been tampered with and that it has been provided by a trusted vendor. Accordingly, patches, service packs, or application components must be signed with a certificate recognized and approved by the organization. Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The application should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.'
  desc 'check', 'Interview the ISSO and/or the SA.

Determine if there is a local procedure to verify the digital signature of the vAMI files prior to being installed on a production system.

If a procedure does not exist or is not being followed, this is a finding.'
  desc 'fix', 'Develop and implement a site procedure to verify the digital signature of the vAMI files prior to being installed on a production system.'
  impact 0.5
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89903r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90211'
  tag rid: 'SV-100861r1_rule'
  tag stig_id: 'VRAU-VA-000170'
  tag gtitle: 'SRG-APP-000131-AS-000002'
  tag fix_id: 'F-96953r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
