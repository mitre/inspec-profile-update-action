control 'SV-221591' do
  title 'WebUSB must be disabled.'
  desc 'Allows you to set whether websites are allowed to get access to connected USB devices. Access can be completely blocked, or the user can be asked every time a website wants to get access to connected USB devices.
If this policy is left not set, ”3” will be used, and the user will be able to change it.
2 = Do not allow any site to request access to USB devices via the WebUSB API
3 = Allow sites to ask the user to grant access to a connected USB device'
  desc 'check', 'Universal method: 
 1. In the omnibox (address bar) type chrome://policy
 2. If "DefaultWebUsbGuardSetting" is not displayed under the "Policy Name" column or it is not set to "2", this is a finding.
Windows method:
 1. Start regedit
 2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
 3. If the "DefaultWebUsbGuardSetting" value name does not exist or its value data is not set to "2", this is a finding.'
  desc 'fix', 'Windows group policy:
 1. Open the “group policy editor” tool with gpedit.msc
 2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\Content Settings
 Policy Name: Control use of the WebUSB API
 Policy State: Enabled
 Policy Value: 2'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23306r415900_chk'
  tag severity: 'medium'
  tag gid: 'V-221591'
  tag rid: 'SV-221591r615937_rule'
  tag stig_id: 'DTBC-0058'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-23295r415901_fix'
  tag 'documentable'
  tag legacy: ['SV-96301', 'V-81587']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
