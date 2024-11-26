control 'SV-27209' do
  title 'All system start-up files must be owned by root.'
  desc 'System start-up files not owned by root could lead to system compromise by allowing malicious users or applications to modify them for unauthorized purposes.  This could lead to system and network compromise.'
  desc 'check', "Check the run control scripts' ownership.
Procedure:
# ls -lL /etc/rc* 
If any run control script is not owned by root or bin, this is a finding."
  desc 'fix', 'Change the ownership of the run control script(s) with incorrect ownership.
# chown root <run control script>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28187r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4089'
  tag rid: 'SV-27209r1_rule'
  tag stig_id: 'GEN001660'
  tag gtitle: 'GEN001660'
  tag fix_id: 'F-4022r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
