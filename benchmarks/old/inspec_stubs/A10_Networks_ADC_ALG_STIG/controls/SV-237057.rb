control 'SV-237057' do
  title 'The A10 Networks ADC, when used for load-balancing web servers, must not allow the HTTP TRACE and OPTIONS methods.'
  desc 'HTTP offers a number of methods that can be used to perform actions on the web server. Some of these HTTP methods can be used for nefarious purposes if the web server is misconfigured. The two HTTP methods used for normal requests are GET and POST, so incoming requests should be limited to those methods.

Although the HTTP TRACE method is useful for debugging, it enables cross-site scripting attacks. By exploiting certain browser vulnerabilities, an attacker may manipulate the TRACE method. The HEAD, GET, POST, and CONNECT methods are generally regarded as safe. For a WAF template, the GET and POST are the default values and are the safest options, so restriction the methods to GET and POST is recommended.'
  desc 'check', 'If the ADC is not used to load balance web servers, this is not applicable. Interview the device administrator to determine which WAF template is used for web servers. 

Review the device configuration.

The following command displays the configuration and filters the output on the WAF template section:
show run | sec slb template waf

If there is no WAF template, this is a finding.

If the WAF template allows the HTTP TRACE method, this is a finding.'
  desc 'fix', 'The following commands configure the ADC to restrict the HTTP methods:
slb template waf [template-name]
allowed-http-methods GET POST HEAD PUT DELETE CONNECT PURGE

Note: GET and POST are the default values and are the safest choices. Restricting the methods to GET and POST is recommended.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40276r639616_chk'
  tag severity: 'medium'
  tag gid: 'V-237057'
  tag rid: 'SV-237057r639618_rule'
  tag stig_id: 'AADC-AG-000122'
  tag gtitle: 'SRG-NET-000401-ALG-000127'
  tag fix_id: 'F-40239r639617_fix'
  tag 'documentable'
  tag legacy: ['SV-82503', 'V-68013']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
