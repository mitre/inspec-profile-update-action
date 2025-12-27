control 'SV-221582' do
  title 'Default behavior must block webpages from automatically running plugins.'
  desc 'This policy allows you to set whether websites are allowed to automatically run the Flash plugin. Automatically running the Flash plugin can be either allowed for all websites or denied for all websites. If this policy is left not set, the user will be able to change this setting manually.    
   1 = Allow all sites to automatically run Flash plugin    
   2 = Block the Flash plugin    
   3 = Click to play'
  desc 'check', 'Universal method: 
 1. In the omnibox (address bar) type chrome://policy 
 2. If the policy "DefaultPluginsSetting" is not shown or is not set to "3", this is a finding.

Windows method:
 1. Start regedit
 2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\DefaultPluginsSetting
 3. If this key "DefaultPluginsSetting" does not exist or is not set to "3", this is a finding.'
  desc 'fix', 'Windows group policy:
   1. Open the group policy editor tool with gpedit.msc   
   2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\Content Settings\\
    Policy Name: Default Flash setting
    Policy State: Enabled
    Policy Value: Click to play'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23297r415873_chk'
  tag severity: 'medium'
  tag gid: 'V-221582'
  tag rid: 'SV-221582r615937_rule'
  tag stig_id: 'DTBC-0040'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-23286r415874_fix'
  tag 'documentable'
  tag legacy: ['SV-57629', 'V-44795']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
