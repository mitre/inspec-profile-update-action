control 'SV-254456' do
  title 'Windows Server 2022 machine inactivity limit must be set to 15 minutes or less, locking the system with the screen saver.'
  desc 'Unattended systems are susceptible to unauthorized use and must be locked when unattended. The screen saver must be set at a maximum of 15 minutes and be password protected. This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.

'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: InactivityTimeoutSecs

Value Type: REG_DWORD
Value: 0x00000384 (900) (or less, excluding "0" which is effectively disabled)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Interactive logon: Machine inactivity limit to "900" seconds or less, excluding "0" which is effectively disabled.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57941r849182_chk'
  tag severity: 'medium'
  tag gid: 'V-254456'
  tag rid: 'SV-254456r849184_rule'
  tag stig_id: 'WN22-SO-000120'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-57892r849183_fix'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000029-GPOS-00010', 'SRG-OS-000031-GPOS-00012']
  tag 'documentable'
  tag cci: ['CCI-000056', 'CCI-000057', 'CCI-000060']
  tag nist: ['AC-11 b', 'AC-11 a', 'AC-11 (1)']
end
