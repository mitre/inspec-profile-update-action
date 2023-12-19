control 'SV-48545' do
  title 'Windows Media Digital Rights Management must be prevented from accessing the Internet.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This check verifies that Windows Media DRM will be prevented from accessing the Internet.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\WMDRM\\

Value Name: DisableOnline

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Digital Rights Management -> "Prevent Windows Media DRM Internet Access" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44934r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15722'
  tag rid: 'SV-48545r2_rule'
  tag stig_id: 'WN08-CC-000120'
  tag gtitle: 'Media DRM – Internet Access'
  tag fix_id: 'F-41391r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
