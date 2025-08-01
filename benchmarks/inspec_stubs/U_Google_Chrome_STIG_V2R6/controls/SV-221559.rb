control 'SV-221559' do
  title 'Site tracking users location must be disabled.'
  desc 'Website tracking is the practice of gathering information as to which websites were accesses by a browser. The common method of doing this is to have a website create a tracking cookie on the browser.   If the information of what sites are being accessed is made available to unauthorized persons, this violates confidentiality requirements, and over time poses a significant OPSEC issue. This policy setting allows you to set whether websites are allowed to track the user’s physical location. Tracking the user’s physical location can be allowed by default, denied by default or the user can be asked every time a website requests the physical location.	
   1 = Allow sites to track the user’s physical location	
   2 = Do not allow any site to track the user’s physical location	
   3 = Ask whenever a site wants to track the user’s physical location'
  desc 'check', 'Universal method:               
   1. In the omnibox (address bar) type chrome://policy             
   2. If DefaultGeolocationSetting is not displayed under the Policy Name column or it is not set to 2, then this is a finding.

Windows method:
   1. Start regedit
   2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
   3. If the DefaultGeolocationSetting value name does not exist or its value data is not set to 2, then this is a finding.'
  desc 'fix', "Windows group policy:    
   1. Open the group policy editor tool with gpedit.msc   
   2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\Content Settings\\    
   Policy Name: Default geolocation setting    
   Policy State: Enabled    
   Policy Value: Do not allow any site to track the users' physical location"
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23274r478199_chk'
  tag severity: 'medium'
  tag gid: 'V-221559'
  tag rid: 'SV-221559r615937_rule'
  tag stig_id: 'DTBC-0002'
  tag gtitle: 'SRG-APP-000206'
  tag fix_id: 'F-23263r478200_fix'
  tag 'documentable'
  tag legacy: ['SV-57557', 'V-44723']
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end
