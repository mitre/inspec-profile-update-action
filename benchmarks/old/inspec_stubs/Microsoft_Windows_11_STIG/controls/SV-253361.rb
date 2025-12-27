control 'SV-253361' do
  title 'Internet connection sharing must be disabled.'
  desc 'Internet connection sharing makes it possible for an existing internet connection, such as through wireless, to be shared and used by other systems essentially creating a mobile hotspot. This exposes the system sharing the connection to others with potentially malicious purpose.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections\\

Value Name: NC_ShowSharedAccessUI

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Network Connections >> "Prohibit use of Internet Connection Sharing on your DNS domain network" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56814r829165_chk'
  tag severity: 'medium'
  tag gid: 'V-253361'
  tag rid: 'SV-253361r829167_rule'
  tag stig_id: 'WN11-CC-000044'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56764r829166_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
