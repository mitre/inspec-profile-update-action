control 'SV-226285' do
  title 'The system must be configured to prevent the display of the last username on the logon screen.'
  desc 'Displaying the username of the last logged on user provides half of the userid/password equation that an unauthorized person would need to gain access.  The username of the last user to log on to a system must not be displayed.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: DontDisplayLastUserName

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive logon: Do not display last user name" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27987r476699_chk'
  tag severity: 'low'
  tag gid: 'V-226285'
  tag rid: 'SV-226285r794586_rule'
  tag stig_id: 'WN12-SO-000018'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27975r476700_fix'
  tag 'documentable'
  tag legacy: ['SV-52941', 'V-11806']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
