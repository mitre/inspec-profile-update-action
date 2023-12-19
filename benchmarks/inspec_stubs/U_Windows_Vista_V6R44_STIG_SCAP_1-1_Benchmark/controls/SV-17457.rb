control 'SV-17457' do
  title 'User Account Control - Behavior of elevation prompt for administrators'
  desc 'This check verifies whether logged on administrator is prompted for consent when he attempts to complete a task that requires raised privileges.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode” to “Prompt for consent”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-14235'
  tag rid: 'SV-17457r1_rule'
  tag gtitle: 'UAC - Admin Elevation Prompt'
  tag fix_id: 'F-16474r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
