control 'SV-3364' do
  title 'MSN Explorer software is installed on the system.'
  desc 'The setup wizard in Windows XP does not allow as much flexibility in component selection as previous version of Windows.  Since that is the case, several default components are installed.  These components must be removed from the system.  These components include MSN Explorer.'
  desc 'check', 'Select “Start”
Select “Control Panel”
Select the “Add or Remove Programs” applet.
Select “Add/Remove Windows Components”.

If the entry for “MSN Explorer” is checked, then this is a finding.'
  desc 'fix', 'Configure the system to remove MSN Explorer.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-564r1_chk'
  tag severity: 'low'
  tag gid: 'V-3364'
  tag rid: 'SV-3364r1_rule'
  tag gtitle: 'MSN Explorer'
  tag fix_id: 'F-5831r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
