control 'SV-218323' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19798r568843_chk'
  tag severity: 'medium'
  tag gid: 'V-218323'
  tag rid: 'SV-218323r603259_rule'
  tag stig_id: 'GEN001680'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19796r568844_fix'
  tag 'documentable'
  tag legacy: ['V-4090', 'SV-63859']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
