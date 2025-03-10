control 'SV-46277' do
  title 'The system must be configured to use TCP syncookies when experiencing a TCP SYN flood.'
  desc "A TCP SYN flood attack can cause Denial of Service by filling a system's TCP connection table with connections in the SYN_RCVD state.  Syncookies are a mechanism used to only track a connection when a subsequent ACK is received, verifying the initiator is attempting a valid connection and is not a flood source.  This technique does not operate in a fully standards-compliant manner, but is only activated when a flood condition is detected, and allows defense of the system while continuing to service valid requests."
  desc 'check', 'Verify the system configured to use TCP syncookies when experiencing a TCP SYN flood.
# cat /proc/sys/net/ipv4/tcp_syncookies
If the result is not "1", this is a finding.'
  desc 'fix', 'Configure the system to use TCP syncookies when experiencing a TCP SYN flood.
Edit /etc/sysctl.conf and add a setting for "net.ipv4.tcp_syncookies=1". 
# sysctl -p'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-36832r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22419'
  tag rid: 'SV-46277r1_rule'
  tag stig_id: 'GEN003612'
  tag gtitle: 'GEN003612'
  tag fix_id: 'F-31670r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001092']
  tag nist: ['SC-5']
end
