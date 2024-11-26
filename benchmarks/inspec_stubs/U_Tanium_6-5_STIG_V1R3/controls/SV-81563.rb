control 'SV-81563' do
  title 'The Tanium Server must be configured to only allow signed content to be imported.'
  desc 'Changes to any software components can have significant effects on the overall security of the application. Verifying software components have been digitally signed using a certificate that is recognized and approved by the organization ensures the software has not been tampered with and that it has been provided by a trusted vendor. 

Accordingly, patches, service packs, or application components must be signed with a certificate recognized and approved by the organization. 

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The application should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.'
  desc 'check', 'NOTE:  This requirement only applies to Tanium implementations in production. If implementation being evaluated is in development, this requirement is Not Applicable.

Access the Tanium Server through interactive logon as an Administrator.

Open an Explorer window.

Navigate to C:\\Program Files\\Tanium\\Tanium Server.

Find the tanium.license file, right-click on the file and choose to Open with WordPad.

When the contents are opened in WordPad, search for "allow unsigned _import". 

If "allow unsigned_import" is followed by ":true", this is not a finding.'
  desc 'fix', 'Contact the Tanium vendor to obtain correct copy of Tanium license file.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67709r2_chk'
  tag severity: 'medium'
  tag gid: 'V-67073'
  tag rid: 'SV-81563r2_rule'
  tag stig_id: 'TANS-SV-000015'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-73173r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
