control 'SV-215382' do
  title 'The sprayd daemon must be disabled on AIX.'
  desc 'The sprayd service is used as a tool to generate UDP packets for testing and diagnosing network problems. The service must be disabled if NFS is not in use, as it can be used by attackers in a Distributed Denial of Service (DDoS) attack.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^sprayd[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "sprayd" entry by running command: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'sprayd' -p 'udp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16580r294597_chk'
  tag severity: 'medium'
  tag gid: 'V-215382'
  tag rid: 'SV-215382r508663_rule'
  tag stig_id: 'AIX7-00-003077'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16578r294598_fix'
  tag 'documentable'
  tag legacy: ['SV-101493', 'V-91395']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
