control 'SV-45073' do
  title 'All system start-up files must be owned by root.'
  desc 'System start-up files not owned by root could lead to system compromise by allowing malicious users or applications to modify them for unauthorized purposes.  This could lead to system and network compromise.'
  desc 'check', %q(Check run control scripts' ownership.
# ls -lL /etc/rc* /etc/init.d

Alternatively:
# find /etc -name "[SK][0-9]*"|xargs stat -L -c %U:%n

If any run control script is not owned by root or bin, this is a finding.)
  desc 'fix', 'Change the ownership of the run control script(s) with incorrect ownership.
# find /etc -name "[SK][0-9]*"|xargs stat -L -c %U:%n|egrep -v "^root:"|cut -d: -f2|xargs chown root'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42445r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4089'
  tag rid: 'SV-45073r1_rule'
  tag stig_id: 'GEN001660'
  tag gtitle: 'GEN001660'
  tag fix_id: 'F-38480r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
