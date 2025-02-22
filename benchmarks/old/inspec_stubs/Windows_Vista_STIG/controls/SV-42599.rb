control 'SV-42599' do
  title 'The External Root CA certificates must be installed in the Trusted Root Store on unclassified systems.'
  desc 'To ensure secure websites protected with External Certificate Authority (ECA) server certificates are properly validated, the system must trust the ECA Root CAs. The ECA root certificates will ensure the trust chain is established for server certificates issued from the External CAs. This requirement only applies to unclassified systems.'
  desc 'fix', 'Install the ECA Root CA certificates on unclassified systems.
ECA Root CA 2
ECA Root CA 4

The InstallRoot tool is available on IASE at http://iase.disa.mil/pki-pke/Pages/tools.aspx.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-32273'
  tag rid: 'SV-42599r4_rule'
  tag stig_id: 'WINPK-000002'
  tag gtitle: 'WINPK-000002'
  tag fix_id: 'F-76959r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
