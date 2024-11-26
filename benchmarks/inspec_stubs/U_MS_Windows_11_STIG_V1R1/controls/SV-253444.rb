control 'SV-253444' do
  title 'The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.'
  desc 'Unattended systems are susceptible to unauthorized use and must be locked when unattended. The screen saver must be set at a maximum of 15 minutes and be password protected. This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.

'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: InactivityTimeoutSecs

Value Type: REG_DWORD
Value: 0x00000384 (900) (or less, excluding "0" which is effectively disabled)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Interactive logon: Machine inactivity limit" to "900" seconds" or less, excluding "0" which is effectively disabled.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56897r829414_chk'
  tag severity: 'medium'
  tag gid: 'V-253444'
  tag rid: 'SV-253444r840185_rule'
  tag stig_id: 'WN11-SO-000070'
  tag gtitle: 'SRG-OS-000279-GPOS-00109'
  tag fix_id: 'F-56847r829415_fix'
  tag satisfies: ['SRG-OS-000279-GPOS-00109', 'SRG-OS-000163-GPOS-00072']
  tag 'documentable'
  tag cci: ['CCI-001133', 'CCI-002331']
  tag nist: ['SC-10', 'AC-19 (5)']
end
