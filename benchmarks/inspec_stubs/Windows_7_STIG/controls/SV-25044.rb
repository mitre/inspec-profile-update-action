control 'SV-25044' do
  title 'The system is configured to allow the display of the last user name on the logon screen.'
  desc 'The user name of the last user to log onto a system will not be displayed.  This eliminates half of the userid/password equation that an unauthorized person would need to log on.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Interactive logon: Do not display last user name” is not set to “Enabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name:  DontDisplayLastUserName

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Interactive logon: Do not display last user name” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-7791r1_chk'
  tag severity: 'low'
  tag gid: 'V-11806'
  tag rid: 'SV-25044r1_rule'
  tag gtitle: 'Display of Last User Name'
  tag fix_id: 'F-11088r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
