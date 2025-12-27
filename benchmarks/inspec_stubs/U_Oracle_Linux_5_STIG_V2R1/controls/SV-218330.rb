control 'SV-218330' do
  title 'All skeleton files (typically those in /etc/skel) must have mode 0644 or less permissive.'
  desc 'If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.'
  desc 'check', 'Check skeleton files permissions.
# ls -alL /etc/skel
If a skeleton file has a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of skeleton files with incorrect mode:
# chmod 0644 <skeleton file>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19805r561440_chk'
  tag severity: 'medium'
  tag gid: 'V-218330'
  tag rid: 'SV-218330r603259_rule'
  tag stig_id: 'GEN001800'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19803r561441_fix'
  tag 'documentable'
  tag legacy: ['V-788', 'SV-63879']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
