control 'SV-42593' do
  title 'The DoD Root CA certificates must be installed in the Trusted Root Store.'
  desc 'To ensure secure DoD websites and DoD-signed code are properly validated, the system must trust the DoD Root Certificate Authorities (CAs). The DoD root certificates will ensure that the trust chain is established for server certificates issued from the DoD CAs.'
  desc 'fix', 'Install the DoD Root CA certificates.
DoD Root CA 2
DoD Root CA 3
DoD Root CA 4

The InstallRoot tool is available on IASE at http://iase.disa.mil/pki-pke/Pages/tools.aspx.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-32272'
  tag rid: 'SV-42593r4_rule'
  tag stig_id: 'WINPK-000001'
  tag gtitle: 'WINPK-000001'
  tag fix_id: 'F-76947r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000185', 'CCI-002470']
  tag nist: ['IA-5 (2) (b) (1)', 'SC-23 (5)']
end
