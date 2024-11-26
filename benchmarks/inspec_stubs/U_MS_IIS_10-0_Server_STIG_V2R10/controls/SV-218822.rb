control 'SV-218822' do
  title 'The IIS 10.0 web server must maintain the confidentiality of controlled information during transmission through the use of an approved Transport Layer Security (TLS) version.'
  desc 'TLS is a required transmission protocol for a web server hosting controlled information. The use of TLS provides confidentiality of data in transit between the web server and client. FIPS 140-2-approved TLS versions must be enabled and non-FIPS-approved SSL versions must be disabled.

NIST SP 800-52 defines the approved TLS versions for government applications.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine which version of TLS is being used.

If the TLS version is not TLS 1.2 or higher, according to NIST SP 800-52, or if non-FIPS-approved algorithms are enabled, this is a finding.'
  desc 'fix', 'Configure the web server to use an approved TLS version according to NIST SP 800-52 and to disable all non-approved versions.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20294r310941_chk'
  tag severity: 'medium'
  tag gid: 'V-218822'
  tag rid: 'SV-218822r879810_rule'
  tag stig_id: 'IIST-SV-000154'
  tag gtitle: 'SRG-APP-000439-WSR-000156'
  tag fix_id: 'F-20292r310942_fix'
  tag 'documentable'
  tag legacy: ['SV-109283', 'V-100179']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
