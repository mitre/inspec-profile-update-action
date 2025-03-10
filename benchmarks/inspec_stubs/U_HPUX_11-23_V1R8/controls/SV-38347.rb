control 'SV-38347' do
  title 'All skeleton files (typically in /etc/skel) must be group-owned by root, bin, sys, system, or other.'
  desc 'If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.'
  desc 'check', 'Verify the skeleton files are group-owned by root, bin, sys, or other.

# ls -alL /etc/skel

If a skeleton file is not group-owned by root, bin, sys, or other, this is a finding'
  desc 'fix', 'Change the group owner of the skeleton file to root, bin, sys, or other.

# chgrp <group> /etc/skel/<skeleton file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36386r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22358'
  tag rid: 'SV-38347r1_rule'
  tag stig_id: 'GEN001830'
  tag gtitle: 'GEN001830'
  tag fix_id: 'F-31725r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
