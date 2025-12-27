control 'SV-215389' do
  title 'The finger daemon must be disabled on AIX.'
  desc 'The fingerd daemon provides the server function for the finger command. This allows users to view real-time pertinent user login information on other remote systems. This service should be disabled as it may provide an attacker with a valid user list to target.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^finger[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "finger" entry by running command: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'finger' -p 'tcp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16587r294618_chk'
  tag severity: 'medium'
  tag gid: 'V-215389'
  tag rid: 'SV-215389r508663_rule'
  tag stig_id: 'AIX7-00-003084'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16585r294619_fix'
  tag 'documentable'
  tag legacy: ['SV-101507', 'V-91409']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
