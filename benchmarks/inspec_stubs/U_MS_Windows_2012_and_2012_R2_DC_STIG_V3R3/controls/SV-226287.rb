control 'SV-226287' do
  title 'The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.'
  desc 'Unattended systems are susceptible to unauthorized use and should be locked when unattended.  The screen saver should be set at a maximum of 15 minutes and be password protected.  This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: InactivityTimeoutSecs

Value Type: REG_DWORD
Value: 0x00000384 (900) (or less, excluding "0" which is effectively disabled)'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive logon: Machine inactivity limit" to "900" seconds" or less, excluding "0" which is effectively disabled.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27989r476705_chk'
  tag severity: 'medium'
  tag gid: 'V-226287'
  tag rid: 'SV-226287r794511_rule'
  tag stig_id: 'WN12-SO-000021'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-27977r476706_fix'
  tag 'documentable'
  tag legacy: ['V-36773', 'SV-51596']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
