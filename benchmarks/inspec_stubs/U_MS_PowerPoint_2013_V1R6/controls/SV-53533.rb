control 'SV-53533' do
  title 'The configuration for Slide Update with counterparts must be disallowed.'
  desc 'This setting controls whether users can link slides in a presentation with their counterparts in a PowerPoint Slide Library.  If this policy setting is enabled, PowerPoint cannot check the status of a slide in a Slide Library when a presentation with Slide Update data is opened.  If this policy setting is disabled or not configured, each time users open a presentation that contains a shared slide, PowerPoint notifies them if the slide has been updated and provides them with the opportunity to ignore the update, append a new slide to the outdated slide, or replace the outdated slide with the updated one.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2013 -> Miscellaneous "Disable Slide Update" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\PowerPoint\\slide libraries

Criteria: If the value DisableSlideUpdate is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2013 -> Miscellaneous "Disable Slide Update" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2013'
  tag check_id: 'C-47695r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26639'
  tag rid: 'SV-53533r1_rule'
  tag stig_id: 'DTOO319'
  tag gtitle: 'DTOO319 - Disable Slide Update'
  tag fix_id: 'F-46458r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
