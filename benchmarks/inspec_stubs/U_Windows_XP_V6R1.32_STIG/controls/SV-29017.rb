control 'SV-29017' do
  title 'The Recovery Console SET command is enabled.'
  desc 'Enabling this option enables the Recovery Console SET command, which allows you to set Recovery Console environment variables.  This permits floppy copy and access to all drives and folders.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Recovery Console: Allow floppy copy and access to all drives and folders” is not set to “Disabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: 
\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Setup\\RecoveryConsole\\

Value Name:  SetCommand

Value Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Recovery Console: Allow floppy copy and access to all drives and folders” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-32725r1_chk'
  tag severity: 'low'
  tag gid: 'V-1158'
  tag rid: 'SV-29017r1_rule'
  tag gtitle: 'Recovery Console - SET Command'
  tag fix_id: 'F-28812r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
end
