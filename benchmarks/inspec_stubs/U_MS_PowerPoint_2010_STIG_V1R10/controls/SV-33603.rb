control 'SV-33603' do
  title 'Automatic download of linked images must be disallowed.'
  desc 'When users insert images into PowerPoint presentations, they can select Link to File instead of Insert. If they do so, the image is represented by a link to a file on disk instead of being embedded in the presentation file itself. By default, when PowerPoint opens a presentation it does not display any linked images saved on a different computer unless the presentation itself is saved in a trusted location (as configured in the Trust Center). If this configuration is changed, PowerPoint will load any images that were saved in remote locations, which presents a security risk.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2010 -> PowerPoint Options -> Security “Unblock automatic download of linked images” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\powerpoint\\security

Criteria: If the value DownloadImages is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2010 -> PowerPoint Options -> Security “Unblock automatic download of linked images” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2010'
  tag check_id: 'C-34068r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17809'
  tag rid: 'SV-33603r1_rule'
  tag stig_id: 'DTOO291 - PowerPoint'
  tag gtitle: 'DTOO291 - Linked images'
  tag fix_id: 'F-29745r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end
