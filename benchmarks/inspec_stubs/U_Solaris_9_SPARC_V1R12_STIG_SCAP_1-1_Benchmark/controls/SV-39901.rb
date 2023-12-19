control 'SV-39901' do
  title 'All skeleton files (typically in /etc/skel) must be group-owned by root, bin, or sys.'
  desc 'If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.'
  desc 'fix', 'Change the group owner of the skeleton file to root.

Procedure:
# chgrp <group> /etc/skel/[skeleton file]'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22358'
  tag rid: 'SV-39901r2_rule'
  tag stig_id: 'GEN001830'
  tag gtitle: 'GEN001830'
  tag fix_id: 'F-34059r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
