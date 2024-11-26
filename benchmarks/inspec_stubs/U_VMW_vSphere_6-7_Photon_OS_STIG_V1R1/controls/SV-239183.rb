control 'SV-239183' do
  title 'The Photon operating system must not perform IPv4 packet forwarding.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.'
  desc 'check', 'At the command line, execute the following command:

# /sbin/sysctl -a --pattern "net.ipv4.ip_forward$"

Expected result:

net.ipv4.ip_forward = 0

If the system is intended to operate as a router, this is N/A.

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'At the command line, execute the following commands:

# sed -i -e "/^net.ipv4.ip_forward/d" /etc/sysctl.conf
# echo net.ipv4.ip_forward=0>>/etc/sysctl.conf'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42394r675355_chk'
  tag severity: 'medium'
  tag gid: 'V-239183'
  tag rid: 'SV-239183r675357_rule'
  tag stig_id: 'PHTN-67-000112'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42353r675356_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
