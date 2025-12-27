control 'SV-242616' do
  title 'The Cisco ISE must audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'Verify logging categories have been configured to send auditable events to the syslog target.

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Categories.
2. Verify the Administrative and Operational Audit is configured for the INFO log severity level.
3. Verify both the Administrative and Operational Audit  and the AAA Audit logging categories have been set to the syslog target.

If the Administrative and Operational Audit (INFO severity) and the AAA Audit logging category is not configured to send to the central syslog server, this is a finding.'
  desc 'fix', 'Enable logging categories for Cisco ISE to send auditable events to the syslog target. 

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Categories.
2. Click the radio button next to the Administrative and Operational Audit logging category and then click "Edit".
3. Choose INFO from the Log Severity Level drop-down list.
4. In the Targets field, move the syslog target name that is being used to the Selected box.
5. Repeat the above steps to enable the AAA Audit logging category. However, this logging category has INFO as the default log severity level and cannot be changed.
5. Click "Save".'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45891r864183_chk'
  tag severity: 'medium'
  tag gid: 'V-242616'
  tag rid: 'SV-242616r864185_rule'
  tag stig_id: 'CSCO-NM-000100'
  tag gtitle: 'SRG-APP-000343-NDM-000289'
  tag fix_id: 'F-45848r864184_fix'
  tag 'documentable'
  tag cci: ['CCI-002264']
  tag nist: ['AC-16 a']
end
