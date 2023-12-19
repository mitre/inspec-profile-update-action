control 'SV-221880' do
  title 'The Oracle Linux operating system must not allow interfaces to perform Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects by default.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table, possibly revealing portions of the network topology."
  desc 'check', 'Verify the system does not allow interfaces to perform IPv4 ICMP redirects by default.

     # grep -r net.ipv4.conf.default.send_redirects /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null

If "net.ipv4.conf.default.send_redirects" is not configured in the "/etc/sysctl.conf" file or in any of the other sysctl.d directories, is commented out or does not have a value of "0", this is a finding.

Check that the operating system implements the "default send_redirects" variables with the following command:

     # /sbin/sysctl -a | grep net.ipv4.conf.default.send_redirects
     net.ipv4.conf.default.send_redirects = 0 

If the returned line does not have a value of "0", this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the system not to allow interfaces to perform IPv4 ICMP redirects by default. 

Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" or a configuration file in the /etc/sysctl.d/ directory (or modify the line to have the required value):

     net.ipv4.conf.default.send_redirects = 0

Issue the following command to make the changes take effect:

     # sysctl --system'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23595r880655_chk'
  tag severity: 'medium'
  tag gid: 'V-221880'
  tag rid: 'SV-221880r880657_rule'
  tag stig_id: 'OL07-00-040650'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23584r880656_fix'
  tag 'documentable'
  tag legacy: ['V-99499', 'SV-108603']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
