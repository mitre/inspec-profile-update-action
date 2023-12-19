control 'SV-237046' do
  title 'To protect against data mining, the A10 Networks ADC providing content filtering must detect SQL injection attacks launched against data storage objects, including, at a minimum, databases, database records, and database fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks launched against organizational databases may result in the compromise of information.

SQL injection attacks are the most prevalent attacks against web applications and databases. These attacks inject SQL commands that can read, modify, or compromise the meaning of the original SQL query. An attacker can spoof identity; expose, tamper, destroy, or make existing data unavailable; or gain unauthorized privileges on the database server.'
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
  tag check_id: 'C-40265r639583_chk'
  tag severity: 'medium'
  tag gid: 'V-237046'
  tag rid: 'SV-237046r639585_rule'
  tag stig_id: 'AADC-AG-000078'
  tag gtitle: 'SRG-NET-000319-ALG-000020'
  tag fix_id: 'F-40228r639584_fix'
  tag 'documentable'
  tag legacy: ['SV-82479', 'V-67989']
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
