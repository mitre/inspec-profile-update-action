control 'SV-91133' do
  title 'Kona Site Defender providing content filtering must block malicious code upon detection.'
  desc 'Taking an appropriate action based on local organizational incident handling procedures minimizes the impact of malicious code on the network.

This requirement is limited to ALGs, web content filters, and packet inspection firewalls that perform malicious code detection as part of their functionality.'
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
  tag check_id: 'C-76097r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76437'
  tag rid: 'SV-91133r1_rule'
  tag stig_id: 'AKSD-WF-000028'
  tag gtitle: 'SRG-NET-000249-ALG-000134'
  tag fix_id: 'F-83115r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
