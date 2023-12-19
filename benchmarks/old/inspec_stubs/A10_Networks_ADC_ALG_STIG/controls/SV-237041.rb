control 'SV-237041' do
  title 'The A10 Networks ADC, when used to load balance web applications, must replace response codes.'
  desc 'Providing too much information in error messages risks compromising the data and security of the application and system. HTTP response codes can be used by an attacker to learn how a web server responds to particular inputs. Certain codes reveal that a security device or the web server defended against a particular attack, which enables the attacker to eliminate that attack as an option. Using ambiguous response codes makes it more difficult for an attacker to determine what defenses are in place. The A10 Networks ADC can be configured to cloak 4xx and 5xx response codes for outbound responses from a web server. The acceptable HTTP response codes are contained in the preconfigured WAF policy file named "allowed_resp_codes".'
  desc 'check', 'If the device is not used to load balance web servers, this is not applicable. If the device is used to load balance web servers, verify that the A10 Networks ADC replaces error response codes.

The following command displays WAF templates:
show slb template waf

If the configured WAF templates do not have the "hide-resp-codes" option configured, this is a finding.'
  desc 'fix', 'If the device is used to load balance web servers, configure the device to replace error response codes.

The following command configures a WAF template and includes the option to cloak response codes:
slb template waf
hide-resp-codes'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40260r639568_chk'
  tag severity: 'medium'
  tag gid: 'V-237041'
  tag rid: 'SV-237041r639570_rule'
  tag stig_id: 'AADC-AG-000063'
  tag gtitle: 'SRG-NET-000273-ALG-000129'
  tag fix_id: 'F-40223r639569_fix'
  tag 'documentable'
  tag legacy: ['SV-82467', 'V-67977']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
