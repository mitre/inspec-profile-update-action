control 'SV-237047' do
  title 'To protect against data mining, the A10 Networks ADC providing content filtering as part of its intermediary services must detect code injection attacks launched against application objects including, at a minimum, application URLs and application code.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks launched against organizational applications may result in the compromise of information.

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
  tag check_id: 'C-40266r639586_chk'
  tag severity: 'medium'
  tag gid: 'V-237047'
  tag rid: 'SV-237047r639588_rule'
  tag stig_id: 'AADC-AG-000079'
  tag gtitle: 'SRG-NET-000319-ALG-000153'
  tag fix_id: 'F-40229r639587_fix'
  tag 'documentable'
  tag legacy: ['SV-82481', 'V-67991']
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
