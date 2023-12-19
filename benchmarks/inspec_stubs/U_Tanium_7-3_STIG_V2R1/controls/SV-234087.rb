control 'SV-234087' do
  title 'The Tanium Server must be configured to only allow signed content to be imported.'
  desc 'Changes to any software components can have significant effects on the overall security of the application. Verifying software components have been digitally signed using a certificate that is recognized and approved by the organization ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Accordingly, patches, service packs, or application components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The application should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.'
  desc 'check', 'Note: This requirement only applies to Tanium implementations in production. If implementation being evaluated is in development, this requirement is Not Applicable.

Access the Tanium Server through interactive logon.

Drill to Program Files >> Tanium >> Tanium Server.

Open the "tanium.license" in Notepad and search for "allow_unsigned_import".

If "allow unsigned_import" is followed by ":true", this is a finding.'
  desc 'fix', 'Contact Tanium for a corrected license file.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37272r610761_chk'
  tag severity: 'medium'
  tag gid: 'V-234087'
  tag rid: 'SV-234087r612749_rule'
  tag stig_id: 'TANS-SV-000015'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-37237r610762_fix'
  tag 'documentable'
  tag legacy: ['SV-102247', 'V-92145']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
