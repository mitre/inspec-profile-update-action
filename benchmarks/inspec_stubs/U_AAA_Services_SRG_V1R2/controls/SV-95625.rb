control 'SV-95625' do
  title 'AAA Services must be configured to encrypt transmitted credentials using a FIPS-validated cryptographic module.'
  desc 'Passwords need to be protected at all times and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

AAA Services can accomplish this by making direct function calls to encryption modules or by leveraging operating system encryption capabilities.'
  desc 'check', "Where passwords are used, verify AAA Services are configured to encrypt transmitted credentials using a FIPS-validated cryptographic module. AAA Services may leverage the capability of an operating system or purpose-built module for this purpose.
 
If AAA Services are not configured to encrypt transmitted credentials using a FIPS-validated cryptographic module, this is a finding.

Note: FIPS-validated cryptographic modules are listed on the NIST Cryptographic Module Validation Program's (CMVP) validation list."
  desc 'fix', 'Configure AAA Services to encrypt transmitted credentials using a FIPS-validated cryptographic module.'
  impact 0.7
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80653r1_chk'
  tag severity: 'high'
  tag gid: 'V-80915'
  tag rid: 'SV-95625r1_rule'
  tag stig_id: 'SRG-APP-000172-AAA-000520'
  tag gtitle: 'SRG-APP-000172-AAA-000520'
  tag fix_id: 'F-87771r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
