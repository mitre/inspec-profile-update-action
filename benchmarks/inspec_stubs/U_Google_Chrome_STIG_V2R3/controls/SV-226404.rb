control 'SV-226404' do
  title 'Import AutoFill form data must be disabled.'
  desc 'This policy forces the autofill form data to be imported from the previous default browser if enabled. If enabled, this policy also affects the import dialog.
If disabled, the autofill form data is not imported.

If it is not set, the user may be asked whether to import, or importing may happen automatically.'
  desc 'check', 'Universal method: 
1. In the omnibox (address bar) type chrome://policy 
2. If ImportAutofillFormData is not displayed under the Policy Name column or it is not set to 0 under the Policy Value column, this is a finding.

Windows method:
1. Start regedit
2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
3. If the ImportAutofillFormData value name does not exist or its value data is not set to 0, this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the "group policy editor" tool with gpedit.msc 
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\
Policy Name: Import autofill form data from default browser on first run
Policy State: Disabled'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-28112r478226_chk'
  tag severity: 'medium'
  tag gid: 'V-226404'
  tag rid: 'SV-226404r615937_rule'
  tag stig_id: 'DTBC-0072'
  tag gtitle: 'SRG-APP-000206'
  tag fix_id: 'F-28100r478227_fix'
  tag 'documentable'
  tag legacy: ['SV-111835', 'V-102873']
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end
