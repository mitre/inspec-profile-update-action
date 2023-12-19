control 'SV-216306' do
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
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17542r371006_chk'
  tag severity: 'medium'
  tag gid: 'V-216306'
  tag rid: 'SV-216306r603267_rule'
  tag stig_id: 'SOL-11.1-020370'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17540r371007_fix'
  tag 'documentable'
  tag legacy: ['V-59841', 'SV-74271']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
