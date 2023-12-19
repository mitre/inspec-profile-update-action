control 'SV-215378' do
  title 'The dtspc daemon must be disabled on AIX.'
  desc "The dtspc service deals with the CDE interface of the X11 daemon. It is started automatically by the inetd daemon in response to a CDE client requesting a process to be started on the daemon's host. This makes it vulnerable to buffer overflow attacks, which may allow an attacker to gain root privileges on a host. This service must be disabled unless it is absolutely required."
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^dtspc[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "dtspc" entry by running command: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'dtspc' -p 'tcp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16576r294585_chk'
  tag severity: 'medium'
  tag gid: 'V-215378'
  tag rid: 'SV-215378r508663_rule'
  tag stig_id: 'AIX7-00-003073'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16574r294586_fix'
  tag 'documentable'
  tag legacy: ['V-91385', 'SV-101483']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
