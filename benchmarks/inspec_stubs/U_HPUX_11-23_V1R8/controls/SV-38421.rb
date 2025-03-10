control 'SV-38421' do
  title 'All system startup files must be group-owned by root, sys, bin or other.'
  desc 'If system startup files do not have a group owner of root or a system group, the files may be modified by malicious users or intruders.'
  desc 'check', 'System start-up files are identified as follows:

Run control scripts reside in the /sbin/init.d directory. 

Links to the run control scripts exist in the /sbin/rc*.d directories. 

Run control script configuration files exist in the /etc/rc.config.d directory. 

Check system start-up script file group ownership.
# ls -lL /sbin/init.d/* /etc/rc.config.d/* /etc/rc.config.d/*

If any system start-up script file is not group-owned by root, sys, bin or other, this is a finding.'
  desc 'fix', 'Change the group ownership of the run control script(s) with incorrect group ownership.

Procedure:
# chgrp root <run control script>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36373r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4090'
  tag rid: 'SV-38421r1_rule'
  tag stig_id: 'GEN001680'
  tag gtitle: 'GEN001680'
  tag fix_id: 'F-31711r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
