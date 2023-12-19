control 'SV-235730' do
  title 'Importing of autofill form data must be disabled.'
  desc 'Allows users to import autofill form data from another browser into Microsoft Edge.

If this policy is enabled, the option to manually import autofill data is automatically selected.

If this policy is disabled, autofill form data is not imported at first run, and users cannot import it manually.

If this policy is not configured, autofill data is imported at first run, and users can choose whether to import this data manually during later browsing sessions.

This policy cannot be set as a recommendation. This means that Microsoft Edge will import autofill data on first run, but users can select or clear autofill data option during manual import.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of autofill form data" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "ImportAutofillFormData" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of autofill form data" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38949r626386_chk'
  tag severity: 'medium'
  tag gid: 'V-235730'
  tag rid: 'SV-235730r626523_rule'
  tag stig_id: 'EDGE-00-000013'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38912r626387_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
