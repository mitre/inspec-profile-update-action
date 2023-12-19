control 'SV-104223' do
  title 'Symantec ProxySG  providing intermediary services for HTTP must inspect outbound HTTP traffic for protocol compliance and protocol anomalies.'
  desc 'Application protocol anomaly detection examines application layer protocols such as HTTP to identify attacks based on observed deviations in the normal RFC behavior of a protocol or service. This type of monitoring allows for the detection of known and unknown exploits that exploit weaknesses of commonly used protocols.

Since protocol anomaly analysis examines the application payload for patterns or anomalies, an HTTP proxy must be included in the ALG. This ALG will be configured to inspect inbound and outbound HTTP communications traffic to detect protocol anomalies such as malformed message and command insertion attacks.'
  desc 'check', 'Check 1 (This is an uncommon configuration. If it is found, it has been deliberately done by the Proxy administrator and cannot/should not be removed without consultation with/advice from the administrator.)
1. Browse to Configuration >> Policy >> Policy Files and click the button to view the installed policy. 
2. Using "<Ctrl>-F", perform a search for the exact terms "detect_protocol(no)". 

If this phrase appears in the policy file, this is a finding.

Discuss with the ProxySG administrator to determine why this was configured and whether an exception must be approved.

Check 2
1. Browse to Configuration >> Services >> Proxy Services, select each HTTP proxy service to be reviewed, and click "Edit Service". 
2. Verify that the "Detect Protocol" checkbox is selected.

If Symantec ProxySG providing intermediary services for HTTP does not inspect inbound HTTP traffic for protocol compliance and protocol anomalies, this is a finding.'
  desc 'fix', 'Configure the ProxySG to perform inbound and outbound HTTP traffic protocol compliance inspection/enforcement.

Fix 1 (This is an uncommon configuration. If it is found, it has been very deliberately done by the Proxy administrator and cannot/should not be removed without consultation with/advice from the administrator.)
1. Browse to Configuration >> Policy >> Policy Files and click the button to view the installed policy. 
2. Using "<Ctrl>-F", perform a search for the exact terms "detect_protocol(no)". 
3. If this phrase appears in the policy, work with the ProxySG administrator to determine why this was configured, whether it can be disabled and if so, how to disable it.

Fix 2
1. Browse to Configuration >> Services >> Proxy Services and select each HTTP proxy service to be reviewed and click "Edit Service". 
2. Select the "Detect Protocol" checkbox and click "OK".
3. Once all services have been modified, click "Apply".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93455r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94269'
  tag rid: 'SV-104223r1_rule'
  tag stig_id: 'SYMP-AG-000270'
  tag gtitle: 'SRG-NET-000512-ALG-000066'
  tag fix_id: 'F-100385r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001125']
  tag nist: ['CM-6 b', 'SC-7 (17)']
end
