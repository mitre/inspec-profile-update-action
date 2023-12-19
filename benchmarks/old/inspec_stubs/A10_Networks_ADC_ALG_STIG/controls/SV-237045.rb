control 'SV-237045' do
  title 'To protect against data mining, the A10 Networks ADC providing content filtering must detect code injection attacks from being launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks launched against organizational databases may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database, or change data on a website. Web applications frequently access databases to store, retrieve, and update information. An attacker can construct inputs that the database will execute. This is most commonly referred to as a code injection attack. This type of attack includes XPath and LDAP injections.'
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
  tag check_id: 'C-40264r639580_chk'
  tag severity: 'medium'
  tag gid: 'V-237045'
  tag rid: 'SV-237045r639582_rule'
  tag stig_id: 'AADC-AG-000077'
  tag gtitle: 'SRG-NET-000319-ALG-000015'
  tag fix_id: 'F-40227r639581_fix'
  tag 'documentable'
  tag legacy: ['SV-82477', 'V-67987']
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
