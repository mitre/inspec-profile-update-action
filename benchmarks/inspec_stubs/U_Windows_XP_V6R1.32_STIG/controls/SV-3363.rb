control 'SV-3363' do
  title 'Microsoft Zone Internet Games are installed on the system.'
  desc 'The setup wizard in Windows XP does not allow as much flexibility in component selection as previous version of Windows.  Since that is the case, several default components are installed.  These components must be removed from the system.  These components include the Microsoft Zone Internet Games.'
  desc 'check', 'Select “Start”
Select “Control Panel”
Select the “Add or Remove Programs” applet.
Select “Add/Remove Windows Components”.
Highlight “Accessories and Utilities”
Highlight “Games” and select details.

If the entry for “Internet Games” is selected, then this is a finding.'
  desc 'fix', 'Configure the system to remove Internet Games.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-563r1_chk'
  tag severity: 'low'
  tag gid: 'V-3363'
  tag rid: 'SV-3363r1_rule'
  tag gtitle: 'Microsoft Zone Internet Games'
  tag fix_id: 'F-5830r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
