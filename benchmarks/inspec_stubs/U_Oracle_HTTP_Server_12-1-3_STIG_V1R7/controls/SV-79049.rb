control 'SV-79049' do
  title 'OHS must have the SSLFIPS directive enabled to maintain the confidentiality of controlled information during transmission through the use of an approved TLS version.'
  desc 'Transport Layer Security (TLS) is a required transmission protocol for a web server hosting controlled information. The use of TLS provides confidentiality of data in transit between the web server and client. FIPS 140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions must be disabled.

NIST SP 800-52 defines the approved TLS versions for government applications.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "SSLFIPS" directive at the OHS server configuration scope.

3. If the directive is omitted or is not set to "On", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "SSLFIPS" directive at the OHS server configuration scope.

3. Set the "SSLFIPS" directive to "On", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65301r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64559'
  tag rid: 'SV-79049r1_rule'
  tag stig_id: 'OH12-1X-000321'
  tag gtitle: 'SRG-APP-000439-WSR-000156'
  tag fix_id: 'F-70489r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
