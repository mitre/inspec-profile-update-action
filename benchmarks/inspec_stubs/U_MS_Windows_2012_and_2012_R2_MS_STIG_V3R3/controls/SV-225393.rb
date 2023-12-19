control 'SV-225393' do
  title 'Windows Media Digital Rights Management (DRM) must be prevented from accessing the Internet.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This check verifies that Windows Media DRM will be prevented from accessing the Internet.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\WMDRM\\

Value Name: DisableOnline

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Digital Rights Management -> "Prevent Windows Media DRM Internet Access" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27092r471521_chk'
  tag severity: 'medium'
  tag gid: 'V-225393'
  tag rid: 'SV-225393r569185_rule'
  tag stig_id: 'WN12-CC-000120'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27080r471522_fix'
  tag 'documentable'
  tag legacy: ['SV-53139', 'V-15722']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
