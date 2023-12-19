control 'SV-225411' do
  title 'The network selection user interface (UI) must not be displayed on the logon screen (Windows 2012 R2).'
  desc 'Enabling interaction with the network selection UI allows users to change connections to available networks without signing into Windows.'
  desc 'check', 'This requirement is NA for the initial release of Windows 2012.  It is applicable to Windows 2012 R2.

Verify the registry value below.  If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

Value Name: DontDisplayNetworkSelectionUI

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'This requirement is NA for the initial release of Windows 2012.  It is applicable to Windows 2012 R2.

Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon -> "Do not display network selection UI" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27110r471575_chk'
  tag severity: 'medium'
  tag gid: 'V-225411'
  tag rid: 'SV-225411r569185_rule'
  tag stig_id: 'WN12-CC-000140'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27098r471576_fix'
  tag 'documentable'
  tag legacy: ['SV-56346', 'V-43240']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
