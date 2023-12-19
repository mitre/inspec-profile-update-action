control 'SV-227672' do
  title 'All skeleton files (typically those in /etc/skel) must have mode 0644 or less permissive.'
  desc 'If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.'
  desc 'check', 'Check skeleton files permissions.
# ls -alL /etc/skel
If a skeleton file has a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of skeleton files with incorrect mode.
# chmod 0644 <skeleton file>'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29834r488594_chk'
  tag severity: 'medium'
  tag gid: 'V-227672'
  tag rid: 'SV-227672r603266_rule'
  tag stig_id: 'GEN001800'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29822r488595_fix'
  tag 'documentable'
  tag legacy: ['V-788', 'SV-788']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
