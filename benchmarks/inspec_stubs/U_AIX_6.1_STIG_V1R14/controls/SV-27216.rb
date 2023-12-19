control 'SV-27216' do
  title 'All system start-up files must be group-owned by sys, bin, other, or system.'
  desc 'If system start-up files do not have a group owner of a system group, the files may be modified by malicious users or intruders.'
  desc 'check', "Check run control scripts' group ownership.

Procedure:
# ls -lL /etc/rc* 

If any run control script is not group-owned by sys, bin, other, or system, this is a finding."
  desc 'fix', 'Change the group ownership of the run control script(s) with incorrect group ownership. 
Procedure: 
# chgrp sys <run control script>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28193r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4090'
  tag rid: 'SV-27216r1_rule'
  tag stig_id: 'GEN001680'
  tag gtitle: 'GEN001680'
  tag fix_id: 'F-34013r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
