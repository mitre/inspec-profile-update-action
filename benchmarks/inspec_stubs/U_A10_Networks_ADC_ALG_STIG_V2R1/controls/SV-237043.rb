control 'SV-237043' do
  title 'To protect against data mining, the A10 Networks ADC must detect and prevent code injection attacks launched against application objects including, at a minimum, application URLs and application code.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to prevent attacks launched against organizational information from unauthorized data mining may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database, or change data on a website. These attacks include buffer overrun, XML, JavaScript, and HTML injections.'
  desc 'check', 'If the ADC is not used to load balance web servers where data can be entered and used in databases or other applications, this is not applicable.

Interview the device administrator to determine which WAF template is used for web servers where data can be entered and used in databases or other applications. Review the device configuration.

The following command displays WAF templates:
show slb template waf

If the configured WAF template does not have the "sqlia-check" option configured, this is a finding.'
  desc 'fix', 'If the ADC is used to load balance web servers where data can be entered and used in databases or other applications, configure the ADC to prevent code injection attacks.

A Web Application Firewall (WAF) template is configured and bound to a virtual port.

The following command configures a WAF template with the SQLIA Check option: 
slb template waf <template name>
sqlia-check [reject | sanitize]

Note: The "sanitize" option is allowed but is not preferred due to the increased CPU load.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40262r639574_chk'
  tag severity: 'medium'
  tag gid: 'V-237043'
  tag rid: 'SV-237043r639576_rule'
  tag stig_id: 'AADC-AG-000075'
  tag gtitle: 'SRG-NET-000318-ALG-000151'
  tag fix_id: 'F-40225r639575_fix'
  tag 'documentable'
  tag legacy: ['SV-82471', 'V-67981']
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
