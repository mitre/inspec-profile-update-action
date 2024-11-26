control 'SV-18444' do
  title 'System halts once an event log has reached its maximum size.'
  desc 'This check verifies that the system will not halt if the audit logs become full.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. Expand the Security Configuration and Analysis tree view. 

Navigate to Local Policies -> Security Options. 

If the value for “Audit: Shut down system immediately if unable to log security audits” is not set to “Disabled”, then this is a finding. 

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa

Value Name:  CrashOnAuditFail

Value Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Audit: Shut down system immediately if unable to log security audits” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-18095r1_chk'
  tag severity: 'low'
  tag gid: 'V-1091'
  tag rid: 'SV-18444r1_rule'
  tag gtitle: 'Halt on Audit Failure'
  tag fix_id: 'F-17292r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECRR-1'
end
