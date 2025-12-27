control 'SV-221586' do
  title 'Deletion of browser history must be disabled.'
  desc 'Disabling this function will prevent users from deleting their browsing history, which could be used to identify malicious websites and files that could later be used for anti-virus and Intrusion Detection System (IDS) signatures. Furthermore, preventing users from deleting browsing history could be used to identify abusive web surfing on government systems.'
  desc 'check', 'Universal method: 
 1. In the omnibox (address bar) type chrome://policy 
 2. If the policy "AllowDeletingBrowserHistory" is not shown or is not set to false, this is a finding.

Windows method:
 1. Start regedit
 2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
 3. If the "AllowDeletingBrowserHistory" value name does not exist or its value data is not set to "0",  this is a finding.'
  desc 'fix', 'Windows group policy:
 1. Open the group policy editor tool with gpedit.msc 
 2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\
 Policy Name: Enable deleting browser and download history
 Policy State: Disabled
 Policy Value: N/A'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23301r415885_chk'
  tag severity: 'medium'
  tag gid: 'V-221586'
  tag rid: 'SV-221586r615937_rule'
  tag stig_id: 'DTBC-0052'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-23290r415886_fix'
  tag 'documentable'
  tag legacy: ['SV-89845', 'V-75165']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
