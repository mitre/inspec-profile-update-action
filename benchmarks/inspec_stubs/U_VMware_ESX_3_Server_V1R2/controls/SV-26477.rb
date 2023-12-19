control 'SV-26477' do
  title 'All skeleton files (typically in /etc/skel) must be group-owned by root, bin, sys, system, or other.'
  desc 'If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.'
  desc 'check', 'Verify the skeleton files are group-owned by root.

Procedure:
# ls -alL /etc/skel

If a skeleton file is not group-owned by root, this is a finding.'
  desc 'fix', 'Change the group owner of the skeleton file to root, bin, sys, system, or other.

Procedure:
# chgrp <group> /etc/skel/[skeleton file]'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27539r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22358'
  tag rid: 'SV-26477r1_rule'
  tag stig_id: 'GEN001830'
  tag gtitle: 'GEN001830'
  tag fix_id: 'F-23706r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
