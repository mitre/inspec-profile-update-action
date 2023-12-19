control 'SV-29021' do
  title 'The Recovery Console option is set to permit automatic logon to the system.'
  desc 'This is a Category 1 finding because if this option is set, the Recovery Console does not require you to provide a password and will automatically log on to the system, giving Administrator access to system files.

By default, the Recovery Console requires you to provide the password for the Administrator account before accessing the system.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Recovery Console: Allow automatic administrative logon” is not set to “Disabled”, then this is a finding. 

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Setup\\RecoveryConsole\\

Value Name:  SecurityLevel

Value Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Recovery Console: Allow automatic administrative logon” to “Disabled”.'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-32726r1_chk'
  tag severity: 'high'
  tag gid: 'V-1159'
  tag rid: 'SV-29021r1_rule'
  tag gtitle: 'Recovery Console - Automatic Logon'
  tag fix_id: 'F-28813r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
end
