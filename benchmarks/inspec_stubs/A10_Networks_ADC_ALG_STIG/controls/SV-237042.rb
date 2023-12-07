control 'SV-237042' do
  title 'To protect against data mining, the A10 Networks ADC must detect and prevent SQL and other code injection attacks launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to prevent attacks launched against organizational information from unauthorized data mining may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database, or change data on a website. Web applications frequently access databases to store, retrieve, and update information. An attacker can construct inputs that the database will execute. This is most commonly referred to as a code injection attack. This type of attack includes XPath and LDAP injections.

The A10 Networks ADC contains a WAF policy file that provides a basic collection of SQL special characters and keywords that are common to SQL injection attacks. The terms in this policy file can trigger commands in the back-end SQL database and allow unauthorized users to obtain sensitive information. If a request contains a term that matches a search definition in the “sqlia_defs” policy file, the device can be configured to sanitize the request of the SQL command or deny the request entirely. The "sanitize" option uses more processor cycles than the preferred option of “drop”.'
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
  tag check_id: 'C-40261r639571_chk'
  tag severity: 'medium'
  tag gid: 'V-237042'
  tag rid: 'SV-237042r639573_rule'
  tag stig_id: 'AADC-AG-000074'
  tag gtitle: 'SRG-NET-000318-ALG-000014'
  tag fix_id: 'F-40224r639572_fix'
  tag 'documentable'
  tag legacy: ['SV-82469', 'V-67979']
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
