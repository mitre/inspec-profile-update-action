control 'SV-230934' do
  title 'Forescout must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc 'Display of the DoD-approved use notification before granting access to the application ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users.

The banner must be formatted in accordance with DTM-08-060.'
  desc 'check', '1. Log on to the Forescout Administrator UI.
2. Select Tools >> Options >> CounterACT User Profiles >> Password and Sessions.
3. Select the Login tab and check the "Display this Notice and Consent Message after login" option.
4. Select the "Before login, prompt user to accept these Terms and Conditions" and view the text.

If the banner is not present or not in exact compliance with the current verbiage and spacing in DTM-08-060, this is a finding.'
  desc 'fix', 'Log on to the Forescout Administrator UI.

1. Select Tools >> Options >> CounterACT User Profiles >> Password and Sessions.
2.  Select the "Login" tab and check the "Display this Notice and Consent Message after login" option.
3. Select the "Before login, prompt user to accept these Terms and Conditions".
4. Copy the exact text and formatting for the Standard Mandatory DoD and Consent Banner into the white box. Be sure to adhere to the exact line spacing required by DTM-08-060.'
  impact 0.3
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33864r603641_chk'
  tag severity: 'low'
  tag gid: 'V-230934'
  tag rid: 'SV-230934r615887_rule'
  tag stig_id: 'FORE-NM-000050'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-33837r603642_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
