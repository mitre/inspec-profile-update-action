control 'SV-218322' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19797r561722_chk'
  tag severity: 'medium'
  tag gid: 'V-218322'
  tag rid: 'SV-218322r603259_rule'
  tag stig_id: 'GEN001660'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19795r561723_fix'
  tag 'documentable'
  tag legacy: ['V-4089', 'SV-63857']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
