control 'SV-48319' do
  title 'The detection of compatibility issues for applications and drivers must be turned off.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\AppCompat\\

Value Name: DisablePcaUI

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Troubleshooting and Diagnostics -> Application Compatibility Diagnostics -> "Detect compatibility issues for applications and drivers" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44991r1_chk'
  tag severity: 'low'
  tag gid: 'V-36696'
  tag rid: 'SV-48319r2_rule'
  tag stig_id: 'WN08-CC-000065'
  tag gtitle: 'WINCC-000065'
  tag fix_id: 'F-41451r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
