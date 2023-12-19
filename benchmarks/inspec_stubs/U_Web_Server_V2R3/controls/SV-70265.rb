control 'SV-70265' do
  title 'A web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version.'
  desc 'Transport Layer Security (TLS) is a required transmission protocol for a web server hosting controlled information. The use of TLS provides confidentiality of data in transit between the web server and client. FIPS 140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions must be disabled.

NIST SP 800-52 defines the approved TLS versions for government applications.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine which version of TLS is being used.

If the TLS version is not an approved version according to NIST SP 800-52 or non-FIPS-approved algorithms are enabled, this is a finding.'
  desc 'fix', 'Configure the web server to use an approved TLS version according to NIST SP 800-52 and to disable all non-approved versions.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-56581r2_chk'
  tag severity: 'medium'
  tag gid: 'V-56011'
  tag rid: 'SV-70265r2_rule'
  tag stig_id: 'SRG-APP-000439-WSR-000156'
  tag gtitle: 'SRG-APP-000439-WSR-000156'
  tag fix_id: 'F-60889r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
