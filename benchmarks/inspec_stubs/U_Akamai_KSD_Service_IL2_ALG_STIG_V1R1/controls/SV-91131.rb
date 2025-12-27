control 'SV-91131' do
  title 'Kona Site Defender providing content filtering must update malicious code protection mechanisms and signature definitions whenever new releases are available in accordance with organizational configuration management policy and procedures.'
  desc 'Malicious code protection mechanisms include but are not limited to anti-virus and malware detection software. To minimize any potential negative impact to the organization caused by malicious code, malicious code must be identified and eradicated. Malicious code includes viruses, worms, trojan horses, and spyware.'
  desc 'check', 'Confirm Kona Site Defender is configured to use the latest rule set to block traffic for organizationally defined HTTP protocol violations, HTTP policy violations, SQL injection, remote file inclusion, cross-site scripting, command injection attacks, and any applicable custom rules:

1. Log in to the Akamai Luna Portal (https://control.akamai.com).
2. Click the "Configure" tab.
3. Under the "Security" section, select "Security Configuration".
4. If prompted for which product to use, select "Site Defender" and then "Continue".
5. For the applicable security configuration, click on the tuning status details link under the "Tuning Status" column.

If the tuning status does not state "You are using the latest Kona Rule Set version and your security configuration is optimal", this is a finding.'
  desc 'fix', 'Configure Kona Site Defender to use the latest rule set to block traffic for organizationally defined HTTP protocol violations, HTTP policy violations, SQL injection, remote file inclusion, cross-site scripting, command injection attacks, and any applicable custom rules:

Contact the Akamai Professional Services team to implement the changes at 1-877-4-AKATEC (1-877-425-2832).'
  impact 0.5
  ref 'DPMS Target Akamai Edge Security ALG'
  tag check_id: 'C-76095r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76435'
  tag rid: 'SV-91131r1_rule'
  tag stig_id: 'AKSD-WF-000026'
  tag gtitle: 'SRG-NET-000246-ALG-000132'
  tag fix_id: 'F-83113r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
