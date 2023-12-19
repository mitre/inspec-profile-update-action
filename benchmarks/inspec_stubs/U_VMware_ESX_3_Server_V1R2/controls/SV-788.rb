control 'SV-788' do
  title 'All skeleton files (typically those in /etc/skel) must have mode 0644 or less permissive.'
  desc 'If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.'
  desc 'check', 'Check skeleton files permissions.
# ls -alL /etc/skel
If a skeleton file has a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of skeleton files with incorrect mode.
# chmod 0644 <skeleton file>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-293r2_chk'
  tag severity: 'medium'
  tag gid: 'V-788'
  tag rid: 'SV-788r2_rule'
  tag stig_id: 'GEN001800'
  tag gtitle: 'GEN001800'
  tag fix_id: 'F-942r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
