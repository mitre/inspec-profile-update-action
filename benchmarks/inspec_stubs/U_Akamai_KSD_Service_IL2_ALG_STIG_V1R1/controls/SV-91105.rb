control 'SV-91105' do
  title 'To protect against data mining, Kona Site Defender providing content filtering must detect code injection attacks launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks launched against organizational databases may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database or change data on a website. Web applications frequently access databases to store, retrieve, and update information. An attacker can construct inputs that the database will execute. This is most commonly referred to as a code injection attack. This type of attack includes XPath and LDAP injections.
 
ALGs with anomaly detection must be configured to protect against unauthorized code injections. These devices must include rules and anomaly detection algorithms to monitor for atypical database queries or accesses. Examples include web application firewalls (WAFs) or database application gateways.'
  desc 'check', 'Confirm Kona Site Defender is configured to block traffic for organizationally defined HTTP protocol violations, HTTP policy violations, SQL injection, remote file inclusion, cross-site scripting, command injection attacks, and any applicable custom rules:

1. Log in to the Akamai Luna Portal (https://control.akamai.com).
2. Click the "Configure" tab.
3. Under the "Security" section, select "Security Configuration".
4. If prompted for which product to use, select "Site Defender" and then "Continue".
5. Under the "Security Configurations" section, click on the most recent version under the "Production" column for the security configuration being reviewed.
6. The detailed "Security Configuration" page will load listing the protected host names and applicable policies.
7. Select the policy being reviewed. 
8. Verify the "Application Layer Controls" checkbox is enabled.
9. Verify the following "KRS Rule Set" rules are set to "Deny".
   - SQL Injection
   - Cross Site Scripting (XSS)
   - Command Injection
   - Invalid HTTP
   - Remote File Inclusion
   - PHP Injection (when PHP is used)
   - Trojan
   - Total Request Scor4e (Inbound)
   - Total Response Score (Outbound)
   - DDOS
10. Verify the "Enabled Slow POST Protection" section appears.

If the application layer controls are not set to "Deny" mode or slow POST protection does not appear, this is a finding.'
  desc 'fix', 'Configure the Kona Site Defender to block traffic for organizationally defined HTTP protocol violations, HTTP policy violations, SQL injection, remote file inclusion, cross-site scripting, command injection attacks, and any applicable custom rules.

The Akamai Professional Services team should be consulted to implement this Fix content due to the complexities involved. In most cases, this should be included in the SLA.

1. Log in to the Akamai Luna Portal (https://control.akamai.com).
2. Click the "Configure" tab.
3. Under the "Security" section, select "Security Configuration".
4. If prompted for which product to use, select "Site Defender" and then "Continue".
5. Under the "Security Configurations" section, click on the most recent version under the "Production" column for the security configuration being reviewed.
6. The detailed "Security Configuration" page will load listing the protected host names and applicable policies.
7. Select the policy being reviewed and click the "Edit" button. 
8. Enable the "Application Layer Controls" box and the "Slow POST Protection" box. 
9. Click the "Next" button and set each of the following "KRS Rule Set" rules to "Deny".
   - SQL Injection
   - Cross Site Scripting (XSS)
   - Command Injection
   - Invalid HTTP
   - Remote File Inclusion
   - PHP Injection (when PHP is used)
   - Trojan
   - Total Request Score (Inbound)
   - Total Response Score (Outbound)
   - DDOS
10. Click the "Next" button and follow the prompts to complete the process.'
  impact 0.5
  ref 'DPMS Target Akamai Edge Security ALG'
  tag check_id: 'C-76065r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76409'
  tag rid: 'SV-91105r1_rule'
  tag stig_id: 'AKSD-WF-000012'
  tag gtitle: 'SRG-NET-000319-ALG-000015'
  tag fix_id: 'F-83085r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
