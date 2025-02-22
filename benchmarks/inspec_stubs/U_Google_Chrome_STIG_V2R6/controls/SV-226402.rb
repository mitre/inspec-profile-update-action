control 'SV-226402' do
  title 'AutoFill for credit cards must be disabled.'
  desc "Enabling Google Chrome's AutoFill feature allows users to auto complete credit card information in web forms using previously stored information.
If this setting is disabled, Autofill will never suggest or fill credit card information, nor will it save additional credit card information that the user might submit while browsing the web.

If this setting is enabled or has no value, the user will be able to control Autofill for credit cards in the UI."
  desc 'check', 'Universal method: 
1. In the omnibox (address bar) type chrome://policy 
2. If AutofillCreditCardEnabled is not displayed under the Policy Name column or it is not set to 0 under the Policy Value column, this is a finding.

Windows method:
1. Start regedit
2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
3. If the AutofillCreditCardEnabled value name does not exist or its value data is not set to 0, this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the "group policy editor" tool with gpedit.msc 
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\
Policy Name: Enable AutoFill for credit cards
Policy State: Disabled'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-28110r478220_chk'
  tag severity: 'medium'
  tag gid: 'V-226402'
  tag rid: 'SV-226402r615937_rule'
  tag stig_id: 'DTBC-0070'
  tag gtitle: 'SRG-APP-000206'
  tag fix_id: 'F-28098r478221_fix'
  tag 'documentable'
  tag legacy: ['SV-111831', 'V-102869']
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end
