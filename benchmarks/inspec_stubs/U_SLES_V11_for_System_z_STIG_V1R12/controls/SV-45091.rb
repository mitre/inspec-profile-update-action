control 'SV-45091' do
  title 'All system start-up files must be group-owned by root, sys, bin, other, or system.'
  desc 'If system start-up files do not have a group owner of root or a system group, the files may be modified by malicious users or intruders.'
  desc 'check', %q(Check run control scripts' group ownership.

Procedure:
# ls -lL /etc/rc* /etc/init.d

Alternatively:
# find /etc -name "[SK][0-9]*"|xargs stat -L -c %G:%n|egrep -v "^(root|sys|bin|other):"
If any run control script is not group-owned by root, sys, bin, or other system groups, this is a finding.)
  desc 'fix', 'Change the group ownership of the run control script(s) with incorrect group ownership.

Procedure:
# chgrp root <run control script>
# find /etc -name "[SK][0-9]*"|xargs stat -L -c %G:%n|egrep -v "^(root|sys|bin|other):"|cut -d: -f2|xargs chgrp root'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42452r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4090'
  tag rid: 'SV-45091r1_rule'
  tag stig_id: 'GEN001680'
  tag gtitle: 'GEN001680'
  tag fix_id: 'F-38494r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
