control 'SV-237040' do
  title 'The A10 Networks ADC, when used to load balance web applications, must strip HTTP response headers.'
  desc 'Providing too much information in error messages risks compromising the data and security of the application and system. HTTP response headers can disclose vulnerabilities about a web server. This information can be used by an attacker. The A10 Networks ADC can filter response headers; this removes the web server’s identifying headers in outgoing responses (such as Server, X-Powered-By, and X-AspNet-Version).'
  desc 'check', 'If the device is not used to load balance web servers, this is not applicable. If the device is used to load balance web servers, verify that the A10 Networks ADC strips HTTP response headers. 

The following command displays WAF templates:
show slb template waf

If the configured WAF templates do not have the "filter-resp-hdrs" option configured, this is a finding.'
  desc 'fix', 'If the device is used to load balance web servers, configure the device to strip HTTP response headers.

The following command configures a WAF template and includes the option to strip HTTP response headers:
slb template waf
filter-resp-hdrs'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40259r639565_chk'
  tag severity: 'medium'
  tag gid: 'V-237040'
  tag rid: 'SV-237040r639567_rule'
  tag stig_id: 'AADC-AG-000062'
  tag gtitle: 'SRG-NET-000273-ALG-000129'
  tag fix_id: 'F-40222r639566_fix'
  tag 'documentable'
  tag legacy: ['SV-82465', 'V-67975']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
