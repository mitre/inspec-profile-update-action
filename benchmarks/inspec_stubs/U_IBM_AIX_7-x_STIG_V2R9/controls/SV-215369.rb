control 'SV-215369' do
  title 'The daytime daemon must be disabled on AIX.'
  desc 'The daytime service provides the current date and time to other servers on a network.

This daytime service is a defunct time service, typically used for testing purposes only. The service should be disabled as it can leave the system vulnerable to DoS ping attacks.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^daytime[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "daytime" entries by running commands: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'daytime' -p 'tcp' 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'daytime' -p 'udp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16567r294558_chk'
  tag severity: 'medium'
  tag gid: 'V-215369'
  tag rid: 'SV-215369r508663_rule'
  tag stig_id: 'AIX7-00-003064'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16565r294559_fix'
  tag 'documentable'
  tag legacy: ['V-91367', 'SV-101465']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
