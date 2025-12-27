control 'SV-226543' do
  title 'All system start-up files must be group-owned by root, sys, or bin.'
  desc 'If system start-up files do not have a group owner of root or a system group, the files may be modified by malicious users or intruders.'
  desc 'check', "Check run control scripts' group ownership.

Procedure:
# ls -lL /etc/rc* /etc/init.d

If any run control script is not group-owned by root, sys, or bin, this is a finding."
  desc 'fix', 'Change the group ownership of the run control script(s) with incorrect group ownership.

Procedure:
# chgrp root <run control script>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28704r483023_chk'
  tag severity: 'medium'
  tag gid: 'V-226543'
  tag rid: 'SV-226543r603265_rule'
  tag stig_id: 'GEN001680'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28692r483024_fix'
  tag 'documentable'
  tag legacy: ['SV-27213', 'V-4090']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
