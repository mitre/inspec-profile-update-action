control 'SV-226401' do
  title 'Guest Mode must be disabled.'
  desc 'If this policy is set to true or not configured, Google Chrome will enable guest logins. Guest logins are Google Chrome profiles where all windows are in incognito mode.

If this policy is set to false, Google Chrome will not allow guest profiles to be started.'
  desc 'check', 'Universal method: 
1. In the omnibox (address bar) type chrome://policy 
2. If BrowserGuestModeEnabled is not displayed under the Policy Name column or it is not set to 0 under the Policy Value column, this is a finding.

Windows method:
1. Start regedit
2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
3. If the BrowserGuestModeEnabled value name does not exist or its value data is not set to 0, this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the "group policy editor" tool with gpedit.msc 
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\
Policy Name: Enable guest mode in browser
Policy State: Disabled'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-28109r478217_chk'
  tag severity: 'medium'
  tag gid: 'V-226401'
  tag rid: 'SV-226401r615937_rule'
  tag stig_id: 'DTBC-0069'
  tag gtitle: 'SRG-APP-000206'
  tag fix_id: 'F-28097r478218_fix'
  tag 'documentable'
  tag legacy: ['SV-111829', 'V-102867']
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end
