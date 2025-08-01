control 'SV-256573' do
  title 'The Photon operating system must use a reverse-path filter for IPv4 network traffic.'
  desc 'Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface they were received on. It should not be used on systems that are routers for complicated networks but is helpful for end hosts and routers serving small networks.'
  desc 'check', 'At the command line, run the following command:

# /sbin/sysctl -a --pattern "net.ipv4.conf.(all|default|eth.*)\\.rp_filter"

Expected result:

net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.eth0.rp_filter = 1

If the output does not match the expected result, this is a finding.

Note: The number of "ethx" lines returned is dependent on the number of interfaces. Every "ethx" entry must be set to "1".'
  desc 'fix', 'At the command line, run the following command:

# for SETTING in $(/sbin/sysctl -aN --pattern "net.ipv4.conf.(all|default|eth.*)\\.rp_filter"); do sed -i -e "/^${SETTING}/d" /etc/sysctl.conf;echo $SETTING=1>>/etc/sysctl.conf; done
# /sbin/sysctl --load'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 vCA Photon OS'
  tag check_id: 'C-60248r887391_chk'
  tag severity: 'medium'
  tag gid: 'V-256573'
  tag rid: 'SV-256573r887393_rule'
  tag stig_id: 'PHTN-30-000104'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60191r887392_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
