control 'SV-208852' do
  title 'IP forwarding for IPv4 must not be enabled, unless the system is a router.'
  desc 'IP forwarding permits the kernel to forward packets from one network interface to another. The ability to forward packets between two networks is only appropriate for systems acting as routers.'
  desc 'check', 'The status of the "net.ipv4.ip_forward" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.ip_forward

The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.ip_forward /etc/sysctl.conf

The ability to forward packets is only appropriate for routers. If the correct value is not returned, this is a finding.'
  desc 'fix', %q(To set the runtime status of the "net.ipv4.ip_forward" kernel parameter, run the following command: 

# sysctl -w net.ipv4.ip_forward=0

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.ip_forward = 0)
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9105r357536_chk'
  tag severity: 'medium'
  tag gid: 'V-208852'
  tag rid: 'SV-208852r603263_rule'
  tag stig_id: 'OL6-00-000082'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9105r357537_fix'
  tag 'documentable'
  tag legacy: ['V-50967', 'SV-65173']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
