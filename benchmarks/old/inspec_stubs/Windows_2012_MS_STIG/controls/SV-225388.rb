control 'SV-225388' do
  title 'The Windows Store application must be turned off.'
  desc 'Uncontrolled installation of applications can introduce various issues, including system instability, and provide access to sensitive information.  Installation of applications must be controlled by the enterprise.  Turning off access to the Windows Store will limit access to publicly available applications.'
  desc 'check', 'The Windows Store is not installed by default. If the \\Windows\\WinStore directory does not exist, this is NA.
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\WindowsStore\\

Value Name:  RemoveWindowsStore

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'The Windows Store is not installed by default.  If the \\Windows\\WinStore directory does not exist, this is NA.

Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Store -> "Turn off the Store application" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27087r471506_chk'
  tag severity: 'medium'
  tag gid: 'V-225388'
  tag rid: 'SV-225388r569185_rule'
  tag stig_id: 'WN12-CC-000110'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27075r471507_fix'
  tag 'documentable'
  tag legacy: ['SV-51751', 'V-36711']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
