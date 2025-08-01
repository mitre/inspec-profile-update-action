control 'SV-221561' do
  title 'Sites ability to show pop-ups must be disabled.'
  desc "Chrome allows you to manage whether unwanted pop-up windows appear. Pop-up windows that are opened when the end user clicks a link are not blocked. If you enable this policy setting, most unwanted pop-up windows are prevented from appearing. If you disable this policy setting, pop-up windows are not prevented from appearing. If you disable this policy setting, scripts can continue to create pop-up windows, and pop-ups that hide other windows. Recommend configuring this setting to ‘2’ to help prevent malicious websites from controlling the pop-up windows or fooling users into clicking on the wrong window.  If you do not configure this policy setting, most unwanted pop-up windows are prevented from appearing.  If this policy is left not set, 'BlockPopups' will be used and the user will be able to change it.    
   1 = Allow all sites to show pop-ups    
   2 = Do not allow any site to show pop-ups"
  desc 'check', 'Universal method: 
 1. In the omnibox (address bar) type chrome://policy 
 2. If DefaultPopupsSetting is not displayed under the Policy Name column or it is not set to 2, then this is a finding.

Windows method:
 1. Start regedit
 2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
 3. If the value name DefaultPopupsSetting does not exist or its value data is not set to 2, then this is a finding.

Note:  If AO Approved exceptions to this rule have been enabled, this is not a finding.'
  desc 'fix', 'Windows group policy:
   1. Open the group policy editor tool with gpedit.msc   
   2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\Content Settings\\
    Policy Name: Default popups setting
    Policy State: Enabled
    Policy Value: Do not allow any site to show popups'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23276r570454_chk'
  tag severity: 'medium'
  tag gid: 'V-221561'
  tag rid: 'SV-221561r615937_rule'
  tag stig_id: 'DTBC-0004'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-23265r478203_fix'
  tag 'documentable'
  tag legacy: ['SV-57553', 'V-44719']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
