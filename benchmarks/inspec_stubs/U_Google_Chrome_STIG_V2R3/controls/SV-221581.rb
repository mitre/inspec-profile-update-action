control 'SV-221581' do
  title 'Browser history must be saved.'
  desc 'This policy disables saving browser history in Google Chrome and prevents users from changing this setting. If this setting is enabled, browsing history is not saved. If this setting is disabled or not set, browsing history is saved.'
  desc 'check', "Universal method:        
   1. In the omnibox (address bar) type chrome://policy        
   2. If the policy 'SavingBrowserHistoryDisabled' is not shown or is not set to false, then this is a finding.

Windows method:
   1. Start regedit
   2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
   3. If the SavingBrowserHistoryDisabled value name does not exist or its value data is not set to 0, then this is a finding."
  desc 'fix', 'Windows group policy:
   1. Open the group policy editor tool with gpedit.msc   
   2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\
    Policy Name: Disable saving browser history
    Policy State: Disabled
    Policy Value:  N/A'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23296r415870_chk'
  tag severity: 'medium'
  tag gid: 'V-221581'
  tag rid: 'SV-221581r615937_rule'
  tag stig_id: 'DTBC-0039'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-23285r415871_fix'
  tag 'documentable'
  tag legacy: ['SV-57627', 'V-44793']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
