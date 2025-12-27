control 'SV-239182' do
  title 'The Photon operating system must not perform multicast packet forwarding.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.'
  desc 'check', 'At the command line, execute the following command:

# /sbin/sysctl -a --pattern "net.ipv[4|6].conf.(all|default|eth.*).mc_forwarding"

Expected result:

net.ipv4.conf.all.mc_forwarding = 0
net.ipv4.conf.default.mc_forwarding = 0
net.ipv4.conf.eth0.mc_forwarding = 0
net.ipv6.conf.all.mc_forwarding = 0
net.ipv6.conf.default.mc_forwarding = 0
net.ipv6.conf.eth0.mc_forwarding = 0

If the output does not match the expected result, this is a finding.

Note: The number of "ethx" lines returned is dependent on the number of interfaces. Every "ethx" entry must be set to "0".'
  desc 'fix', 'At the command line, execute the following command:

# for SETTING in $(/sbin/sysctl -aN --pattern "net.ipv[4|6].conf.(all|default|eth.*).mc_forwarding"); do sed -i -e "/^${SETTING}/d" /etc/sysctl.conf;echo $SETTING=0>>/etc/sysctl.conf; done'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42393r675352_chk'
  tag severity: 'medium'
  tag gid: 'V-239182'
  tag rid: 'SV-239182r675354_rule'
  tag stig_id: 'PHTN-67-000111'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42352r675353_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
