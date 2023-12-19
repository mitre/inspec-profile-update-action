control 'SV-48341' do
  title 'Automatic download of updates from the Windows Store must be turned off.'
  desc 'Uncontrolled system updates can introduce issues to a system.  Obtaining update components from an outside source may also potentially allow sensitive information outside of the enterprise.  Application updates must be obtained from an internal source.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\WindowsStore\\

Value Name: AutoDownload

Type: REG_DWORD
Value: 0x00000002 (2)'
  desc 'fix', 'Windows 8.1 split the original policy that configures this setting into two separate ones. Configuring either one to "Enabled" will update the registry value as identified in the Check section.

Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Store >> "Turn off Automatic Download of updates on Win8 machines" or "Turn off Automatic Download and install of updates" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-66257r1_chk'
  tag severity: 'low'
  tag gid: 'V-36710'
  tag rid: 'SV-48341r4_rule'
  tag stig_id: 'WN08-CC-000109'
  tag gtitle: 'WINCC-000109'
  tag fix_id: 'F-71643r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
