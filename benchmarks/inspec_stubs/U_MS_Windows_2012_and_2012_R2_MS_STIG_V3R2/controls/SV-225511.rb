control 'SV-225511' do
  title 'The shutdown option must not be available from the logon dialog box.'
  desc "Displaying the shutdown button may allow individuals to shut down a system anonymously.  Only authenticated users should be allowed to shut down the system.  Preventing display of this button in the logon dialog box ensures that individuals who shut down the system are authorized and tracked in the system's Security event log."
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: ShutdownWithoutLogon

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Shutdown: Allow system to be shutdown without having to log on" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27210r471875_chk'
  tag severity: 'low'
  tag gid: 'V-225511'
  tag rid: 'SV-225511r569185_rule'
  tag stig_id: 'WN12-SO-000073'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27198r471876_fix'
  tag 'documentable'
  tag legacy: ['SV-52840', 'V-1075']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
