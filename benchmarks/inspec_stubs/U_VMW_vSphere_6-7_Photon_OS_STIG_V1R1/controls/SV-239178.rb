control 'SV-239178' do
  title 'The Photon operating system must prevent IPv4 Internet Control Message Protocol (ICMP) secure redirect messages from being accepted.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack."
  desc 'check', 'At the command line, execute the following command:

# /sbin/sysctl -a --pattern "net.ipv4.conf.(all|default|eth.*).secure_redirects"

Expected result:

net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.eth0.secure_redirects = 0

If the output does not match the expected result, this is a finding.

Note: The number of "ethx" lines returned is dependent on the number of interfaces. Every "ethx" entry must be set to "0".'
  desc 'fix', 'At the command line, execute the following command:

# for SETTING in $(/sbin/sysctl -aN --pattern "net.ipv4.conf.(all|default|eth.*).secure_redirects"); do sed -i -e "/^${SETTING}/d" /etc/sysctl.conf;echo $SETTING=0>>/etc/sysctl.conf; done'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42389r675340_chk'
  tag severity: 'medium'
  tag gid: 'V-239178'
  tag rid: 'SV-239178r675342_rule'
  tag stig_id: 'PHTN-67-000107'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42348r675341_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
