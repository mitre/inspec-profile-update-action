control 'SV-91147' do
  title 'Kona Site Defender must check the validity of all data inputs except those specifically identified by the organization.'
  desc "Invalid user input occurs when a user inserts data or characters into an application's data entry fields and the application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application or information system compromise. Invalid input is one of the primary methods employed when attempting to compromise an application.

Network devices with the functionality to perform application layer inspection may be leveraged to validate data content of network communications. Checking the valid syntax and semantics of information system inputs (e.g., character set, length, numerical range, and acceptable values) verifies that inputs match specified definitions for format and content. Software typically follows well-defined protocols that use structured messages (i.e., commands or queries) to communicate between software modules or system components.

Structured messages can contain raw or unstructured data interspersed with metadata or control information. If network elements use attacker-supplied inputs to construct structured messages without properly encoding such messages, the attacker could insert malicious commands or special characters that can cause the data to be interpreted as control information or metadata. Consequently, the module or component that receives the tainted output will perform the wrong operations or otherwise interpret the data incorrectly.

Pre-screening inputs prior to passing to interpreters prevents the content from being unintentionally interpreted as commands. Input validation helps to ensure accurate and correct inputs and prevent attacks such as cross-site scripting and a variety of injection attacks.

This requirement applies to gateways and firewalls that perform content inspection or have higher-layer proxy functionality."
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
  tag check_id: 'C-76111r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76451'
  tag rid: 'SV-91147r1_rule'
  tag stig_id: 'AKSD-WF-000037'
  tag gtitle: 'SRG-NET-000401-ALG-000127'
  tag fix_id: 'F-83129r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
