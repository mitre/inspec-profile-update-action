control 'SV-215258' do
  title 'AIX telnet daemon must not be running.'
  desc 'This telnet service is used to service remote user connections. This is historically the most commonly used remote access method for UNIX servers. The username and passwords are passed over the network in clear text and therefore insecurely. Unless required the telnetd daemon will be disabled. This function, if required, should be facilitated through SSH.'
  desc 'check', %q(Determine if the "telnet" daemon is running by running the following command:
# grep -v '^#' /etc/inetd.conf | grep telnet 

If an entry is returned, this is a finding.)
  desc 'fix', %q(Disable the "telnet" entry in "/etc/inetd.conf" using command: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'telnet' -p 'tcp6' 

Reload the inetd process:
# refresh -s inetd)
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16456r294225_chk'
  tag severity: 'high'
  tag gid: 'V-215258'
  tag rid: 'SV-215258r508663_rule'
  tag stig_id: 'AIX7-00-002059'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-16454r294226_fix'
  tag 'documentable'
  tag legacy: ['SV-101403', 'V-91305']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
