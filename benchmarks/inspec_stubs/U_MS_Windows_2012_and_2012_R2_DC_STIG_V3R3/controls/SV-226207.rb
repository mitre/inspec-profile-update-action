control 'SV-226207' do
  title 'Automatic download of updates from the Windows Store must be turned off.'
  desc 'Uncontrolled system updates can introduce issues to a system.  Obtaining update components from an outside source may also potentially allow sensitive information outside of the enterprise.  Application updates must be obtained from an internal source.'
  desc 'check', 'The Windows Store is not installed by default.  If the \\Windows\\WinStore directory does not exist, this is NA.
If the following registry value does not exist or is not configured as specified, this is a finding:

Windows 2012 R2:
Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\WindowsStore\\

Value Name:  AutoDownload

Type:  REG_DWORD
Value:  0x00000002 (2)

Windows 2012:
Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\WindowsStore\\WindowsUpdate\\

Value Name:  AutoDownload

Type:  REG_DWORD
Value:  0x00000002 (2)'
  desc 'fix', 'The Windows Store is not installed by default.  If the \\Windows\\WinStore directory does not exist, this is NA.

Windows 2012 R2:
Windows 2012 R2 split the original policy that configures this setting into two separate ones.  Configuring either one to "Enabled" will update the registry value as identified in the Check section.

Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Store -> 
"Turn off Automatic Download of updates on Win8 machines" or "Turn off Automatic Download and install of updates" to "Enabled".

Windows 2012:
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Store -> "Turn off Automatic Download of updates" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27909r475944_chk'
  tag severity: 'low'
  tag gid: 'V-226207'
  tag rid: 'SV-226207r794443_rule'
  tag stig_id: 'WN12-CC-000109'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27897r475945_fix'
  tag 'documentable'
  tag legacy: ['V-36710', 'SV-51750']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
