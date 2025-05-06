control 'SV-217913' do
  title 'IP forwarding for IPv4 must not be enabled, unless the system is a router.'
  desc 'IP forwarding permits the kernel to forward packets from one network interface to another. The ability to forward packets between two networks is only appropriate for systems acting as routers.'
  desc 'check', 'The status of the "net.ipv4.ip_forward" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.ip_forward
net.ipv4.ip_forward = 0

$ grep net.ipv4.ip_forward /etc/sysctl.conf /etc/sysctl.d/*
net.ipv4.ip_forward = 0

If "net.ipv4.ip_forward" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out or does not have a value of "0", this is a finding.'
  desc 'fix', 'To set the runtime status of the "net.ipv4.ip_forward" kernel parameter, run the following command: 

# sysctl -w net.ipv4.ip_forward=0

Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" or a config file in the /etc/sysctl.d/ directory (or modify the line to have the required value): 

net.ipv4.ip_forward = 0

Issue the following command to make the changes take effect:

# sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19394r376754_chk'
  tag severity: 'medium'
  tag gid: 'V-217913'
  tag rid: 'SV-217913r603264_rule'
  tag stig_id: 'RHEL-06-000082'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19392r376755_fix'
  tag 'documentable'
  tag legacy: ['V-38511', 'SV-50312']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
