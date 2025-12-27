control 'SV-215370' do
  title 'The cmsd daemon must be disabled on AIX.'
  desc 'This is a calendar and appointment service for CDE.

The cmsd service is utilized by CDE to provide calendar functionality. If CDE is not required, this service should be disabled to prevent attacks.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^#cmsd[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "cmsd" entry by running command:
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'cmsd' -p 'sunrpc_udp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16568r294561_chk'
  tag severity: 'medium'
  tag gid: 'V-215370'
  tag rid: 'SV-215370r508663_rule'
  tag stig_id: 'AIX7-00-003065'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16566r294562_fix'
  tag 'documentable'
  tag legacy: ['SV-101467', 'V-91369']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
