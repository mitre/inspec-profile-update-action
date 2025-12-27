control 'SV-204758' do
  title 'The application server must utilize FIPS 140-2 approved encryption modules when authenticating users and processes.'
  desc 'Encryption is only as good as the encryption modules utilized.  Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms.  The use of TLS provides confidentiality of data in transit between the application server and client.  

TLS must be enabled and non-FIPS-approved SSL versions must be disabled.  NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', 'Review the application server documentation and deployed configuration to determine which version of TLS is being used.

If the application server is not using TLS when authenticating users or non-FIPS-approved SSL versions are enabled, this is a finding.'
  desc 'fix', 'Configure the application server to use a FIPS-2 approved TLS version to authenticate users and to disable all non-FIPS-approved SSL versions.'
  impact 0.7
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4878r282921_chk'
  tag severity: 'high'
  tag gid: 'V-204758'
  tag rid: 'SV-204758r864567_rule'
  tag stig_id: 'SRG-APP-000179-AS-000129'
  tag gtitle: 'SRG-APP-000179'
  tag fix_id: 'F-4878r282922_fix'
  tag 'documentable'
  tag legacy: ['SV-46616', 'V-35329']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
