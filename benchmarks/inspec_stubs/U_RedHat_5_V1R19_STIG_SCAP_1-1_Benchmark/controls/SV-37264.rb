control 'SV-37264' do
  title 'All system start-up files must be owned by root.'
  desc 'System start-up files not owned by root could lead to system compromise by allowing malicious users or applications to modify them for unauthorized purposes.  This could lead to system and network compromise.'
  desc 'fix', 'Change the ownership of the run control script(s) with incorrect ownership.
# find /etc -name "[SK][0-9]*"|xargs stat -L -c %U:%n|egrep -v "^root:"|cut -d: -f2|xargs chown root'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-4089'
  tag rid: 'SV-37264r1_rule'
  tag stig_id: 'GEN001660'
  tag gtitle: 'GEN001660'
  tag fix_id: 'F-31210r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
