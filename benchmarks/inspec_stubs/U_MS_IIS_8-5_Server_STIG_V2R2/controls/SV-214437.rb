control 'SV-214437' do
  title 'A web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version.'
  desc 'Transport Layer Security (TLS) is a required transmission protocol for a web server hosting controlled information. The use of TLS provides confidentiality of data in transit between the web server and client. FIPS 140-2-approved TLS versions must be enabled and non-FIPS-approved SSL versions must be disabled.

NIST SP 800-52 defines the approved TLS versions for government applications.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine which version of TLS is being used.

If the TLS version is not TLS 1.2 or higher, according to NIST SP 800-52, or if non-FIPS-approved algorithms are enabled, this is a finding.'
  desc 'fix', 'Configure the web server to use an approved TLS version according to NIST SP 800-52 and to disable all non-approved versions.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Server'
  tag check_id: 'C-15647r505375_chk'
  tag severity: 'medium'
  tag gid: 'V-214437'
  tag rid: 'SV-214437r508658_rule'
  tag stig_id: 'IISW-SV-000154'
  tag gtitle: 'SRG-APP-000439-WSR-000156'
  tag fix_id: 'F-15645r505376_fix'
  tag 'documentable'
  tag legacy: ['SV-91457', 'V-76761']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
