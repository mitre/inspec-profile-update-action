control 'SV-237060' do
  title 'The A10 Networks ADC, when used for load balancing web servers, must deploy the WAF in active mode.'
  desc 'The Web Application Firewall (WAF) supports three operational modes - Learning, Passive, and Active. Active is the standard operational mode and must be used in order to drop or sanitize traffic. Learning mode is used in lab environments to initially set thresholds for certain WAF checks and should not be used in production networks. Passive mode applies enabled WAF checks, but no action is taken upon matching traffic. This mode is useful in identifying false positives for filtering. Only Active mode filters web traffic.'
  desc 'check', 'Review the device configuration.

The following command displays the configuration and filters the output on the WAF template section:
show run | sec slb template waf

If the output contains either "deploy-mode passive" or "deploy-mode learning", this is a finding.

Note: Since deploy-mode active is the default value, it will not appear in the output.'
  desc 'fix', 'The following command sets the deployment mode of the WAF template:
slb template waf [template name]
deploy-mode active'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40279r639625_chk'
  tag severity: 'medium'
  tag gid: 'V-237060'
  tag rid: 'SV-237060r639627_rule'
  tag stig_id: 'AADC-AG-000143'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-40242r639626_fix'
  tag 'documentable'
  tag legacy: ['SV-82511', 'V-68021']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
