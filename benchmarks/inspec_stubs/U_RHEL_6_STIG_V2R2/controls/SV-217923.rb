control 'SV-217923' do
  title 'The system must be configured to use TCP syncookies when experiencing a TCP SYN flood.'
  desc "A TCP SYN flood attack can cause a denial of service by filling a system's TCP connection table with connections in the SYN_RCVD state. Syncookies can be used to track a connection when a subsequent ACK is received, verifying the initiator is attempting a valid connection and is not a flood source. This feature is activated when a flood condition is detected, and enables the system to continue servicing valid connection requests."
  desc 'check', 'The status of the "net.ipv4.tcp_syncookies" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.tcp_syncookies
net.ipv4.tcp_syncookies = 1

$ grep net.ipv4.tcp_syncookies /etc/sysctl.conf /etc/sysctl.d/*
net.ipv4.tcp_syncookies = 1

If "net.ipv4.tcp_syncookies" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out or does not have a value of "1", this is a finding.'
  desc 'fix', 'To set the runtime status of the "net.ipv4.tcp_syncookies" kernel parameter, run the following command: 

# sysctl -w net.ipv4.tcp_syncookies=1

Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" or a config file in the /etc/sysctl.d/ directory (or modify the line to have the required value): 

net.ipv4.tcp_syncookies = 1   

Issue the following command to make the changes take effect:

# sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19404r376784_chk'
  tag severity: 'medium'
  tag gid: 'V-217923'
  tag rid: 'SV-217923r603264_rule'
  tag stig_id: 'RHEL-06-000095'
  tag gtitle: 'SRG-OS-000142'
  tag fix_id: 'F-19402r376785_fix'
  tag 'documentable'
  tag legacy: ['V-38539', 'SV-50340']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
