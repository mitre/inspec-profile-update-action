control 'SV-241787' do
  title 'Web Bluetooth API must be disabled.'
  desc 'Setting the policy to 3 lets websites ask for access to nearby Bluetooth devices. Setting the policy to 2 denies access to nearby Bluetooth devices.

Leaving the policy unset lets sites ask for access, but users can change this setting.

2 = Do not allow any site to request access to Bluetooth devices via the Web Bluetooth API
3 = Allow sites to ask the user to grant access to a nearby Bluetooth device'
  desc 'check', 'Universal method: 
1. In the omnibox (address bar) type chrome://policy 
2. If DefaultWebBluetoothGuardSetting is not displayed under the Policy Name column or it is not set to 2 under the Policy Value column, then this is a finding.

Windows method:
 1. Start regedit
 2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
 3. If the DefaultWebBluetoothGuardSetting value name does not exist or its value data is not set to 2, then this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the “group policy editor” tool with gpedit.msc
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\Content Settings
 Policy Name: Control use of the Web Bluetooth API
 Policy State: Enabled
 Policy Value: Do not allow any site to request access to Bluetooth devices via the Web Bluetooth API'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-45063r684828_chk'
  tag severity: 'medium'
  tag gid: 'V-241787'
  tag rid: 'SV-241787r720329_rule'
  tag stig_id: 'DTBC-0073'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-45022r720328_fix'
  tag 'documentable'
  tag legacy: ['SV-34246', 'V-26961']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
