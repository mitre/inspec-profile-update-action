control 'SV-239179' do
  title 'The Photon operating system must not send IPv4 Internet Control Message Protocol (ICMP) redirects.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table, possibly revealing portions of the network topology."
  desc 'check', 'At the command line, execute the following command:

# /sbin/sysctl -a --pattern "net.ipv4.conf.(all|default|eth.*).send_redirects"

Expected result:

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.eth0.send_redirects = 0

If the output does not match the expected result, this is a finding.

Note: The number of "ethx" lines returned is dependent on the number of interfaces. Every "ethx" entry must be set to "0".'
  desc 'fix', 'Open /etc/sysctl.conf with a text editor.

Add or update the following lines:

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.eth0.send_redirects = 0

Run the following command to load the new setting:

# /sbin/sysctl --load'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42390r675343_chk'
  tag severity: 'medium'
  tag gid: 'V-239179'
  tag rid: 'SV-239179r816664_rule'
  tag stig_id: 'PHTN-67-000108'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42349r816663_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
