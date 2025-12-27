control 'SV-45139' do
  title 'All skeleton files (typically in /etc/skel) must be group-owned by root, bin or sys.'
  desc 'If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.'
  desc 'check', 'Verify the skeleton files are group-owned by root, bin or sys.

Procedure:
# ls -alL /etc/skel
If a skeleton file is not group-owned by root, bin or sys this is a finding.'
  desc 'fix', 'Change the group-owner of the skeleton file to root, bin or sys. 

Procedure:
# chgrp <group> /etc/skel/<skeleton file>
or:
# cd /etc/skel
# ls -L /etc/skel|xargs stat -L -c %G:%n|egrep -v "^(root|bin|sys):"|cut -d: -f2|xargs chgrp root
will change the group of all files not already in one of the approved groups to root.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42482r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22358'
  tag rid: 'SV-45139r2_rule'
  tag stig_id: 'GEN001830'
  tag gtitle: 'GEN001830'
  tag fix_id: 'F-38535r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
