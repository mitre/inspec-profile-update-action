control 'SV-208862' do
  title 'The system must be configured to use TCP syncookies when experiencing a TCP SYN flood.'
  desc "A TCP SYN flood attack can cause a denial of service by filling a system's TCP connection table with connections in the SYN_RCVD state. Syncookies can be used to track a connection when a subsequent ACK is received, verifying the initiator is attempting a valid connection and is not a flood source. This feature is activated when a flood condition is detected, and enables the system to continue servicing valid connection requests."
  desc 'check', 'The status of the "net.ipv4.tcp_syncookies" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.tcp_syncookies

The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.tcp_syncookies /etc/sysctl.conf

If the correct value is not returned, this is a finding.'
  desc 'fix', %q(To set the runtime status of the "net.ipv4.tcp_syncookies" kernel parameter, run the following command: 

# sysctl -w net.ipv4.tcp_syncookies=1

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.tcp_syncookies = 1)
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9115r357566_chk'
  tag severity: 'medium'
  tag gid: 'V-208862'
  tag rid: 'SV-208862r793647_rule'
  tag stig_id: 'OL6-00-000095'
  tag gtitle: 'SRG-OS-000142'
  tag fix_id: 'F-9115r357567_fix'
  tag 'documentable'
  tag legacy: ['V-50683', 'SV-64889']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
