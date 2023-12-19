control 'SV-214221' do
  title 'The Infoblox system must be configured to display the appropriate security classification information.'
  desc 'Configuration of the informational banner displays the security classification of the Infoblox system using both color and text. Text may be added for additional security markings.'
  desc 'check', 'Log on to the Infoblox Grid Master. The appropriate security classification color and text must be displayed on the top of each configuration screen. The output will also contain the text "Dynamic Page - Highest Possible Classification Is" and a colored bar with the classification. Additional text may appear if configured by the administrator.

If the security classification color and text are not displayed at the top of each configuration screen, this is a finding.'
  desc 'fix', 'Navigate to Grid >> Grid Manager >> Grid Properties.

Select "Security", advanced tab.
Click "Enable Security Banner". Use the drop-down menus to select the security level to be displayed and background color appropriate for each level. Additional text can be entered if required by DoD or local policy.
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.3
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15436r295926_chk'
  tag severity: 'low'
  tag gid: 'V-214221'
  tag rid: 'SV-214221r612370_rule'
  tag stig_id: 'IDNS-7X-000960'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-15434r295927_fix'
  tag 'documentable'
  tag legacy: ['SV-83119', 'V-68629']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
