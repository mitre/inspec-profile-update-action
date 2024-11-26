control 'SV-34090' do
  title 'The configuration for Slide Update with counterparts must be disallowed.'
  desc 'This setting controls whether users can link slides in a presentation with their counterparts in a PowerPoint Slide Library.  If you enable this policy setting, PowerPoint cannot check the status of a slide in a Slide Library when a presentation with Slide Update data is opened.  If you disable or do not configure this policy setting, each time users open a presentation that contains a shared slide, PowerPoint notifies them if the slide has been updated and provides them with the opportunity to ignore the update, append a new slide to the outdated slide, or replace the outdated slide with the updated one.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2010 -> Miscellaneous “Disable Slide Update” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\powerpoint\\slide libraries

Criteria: If the value DisableSlideUpdate is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2010 -> Miscellaneous “Disable Slide Update” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2010'
  tag check_id: 'C-34239r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26639'
  tag rid: 'SV-34090r1_rule'
  tag stig_id: 'DTOO319 - PowerPoint'
  tag gtitle: 'DTOO319 - Disable Slide Update'
  tag fix_id: 'F-29933r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
