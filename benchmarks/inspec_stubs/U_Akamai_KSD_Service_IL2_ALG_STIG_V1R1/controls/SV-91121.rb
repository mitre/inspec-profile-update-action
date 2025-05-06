control 'SV-91121' do
  title 'Kona Site Defender that provides intermediary services for HTTP must inspect inbound and outbound HTTP traffic for protocol compliance and protocol anomalies.'
  desc 'Application protocol anomaly detection examines application layer protocols such as HTTP to identify attacks based on observed deviations in the normal RFC behavior of a protocol or service. This type of monitoring allows for the detection of known and unknown exploits that exploit weaknesses of commonly used protocols.

Since protocol anomaly analysis examines the application payload for patterns or anomalies, an HTTP proxy must be included in the ALG. This ALG will be configured to inspect inbound and outbound HTTP communications traffic to detect protocol anomalies such as malformed message and command insertion attacks.

All inbound and outbound traffic, including HTTPS, must be inspected. However, the intention of this policy is not to mandate HTTPS inspection by the ALG. Typically, HTTPS traffic is inspected at the source or destination and/or is directed for inspection by an organizationally defined network termination point.'
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
  tag check_id: 'C-76085r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76425'
  tag rid: 'SV-91121r1_rule'
  tag stig_id: 'AKSD-WF-000021'
  tag gtitle: 'SRG-NET-000512-ALG-000066'
  tag fix_id: 'F-83103r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001125']
  tag nist: ['CM-6 b', 'SC-7 (17)']
end
