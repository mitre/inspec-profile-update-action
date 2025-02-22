control 'SV-38420' do
  title 'All system start-up files must be owned by root.'
  desc 'System start-up files not owned by root could lead to system compromise by allowing malicious users or applications to modify them for unauthorized purposes.  This could lead to system and network compromise.'
  desc 'check', 'System start-up files are identified as follows: 

Run control scripts reside in the /sbin/init.d directory. 

Links to the run control scripts exist in the /sbin/rc*.d directories. 

Run control configuration files exist in the /etc/rc.config.d directory. 

Check all system start-up script file ownership.
# ls -lL  /sbin/init.d/*  /sbin/rc*.d/* /etc/rc.config.d/*

If any system start-up script file is not owned by root or bin, this is a finding.'
  desc 'fix', 'Change the ownership of the run control script(s) with incorrect ownership.
# chown root <run control script>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36372r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4089'
  tag rid: 'SV-38420r1_rule'
  tag stig_id: 'GEN001660'
  tag gtitle: 'GEN001660'
  tag fix_id: 'F-31709r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
