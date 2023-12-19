control 'SV-239176' do
  title 'The Photon operating system must not respond to IPv4 Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.'
  desc 'Responding to broadcast (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.'
  desc 'check', 'At the command line, execute the following command:

# /sbin/sysctl -a --pattern ignore_broadcasts

Expected result:

net.ipv4.icmp_echo_ignore_broadcasts = 1

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'At the command line, execute the following commands:

# sed -i -e "/^net.ipv4.icmp_echo_ignore_broadcasts/d" /etc/sysctl.conf
# echo net.ipv4.icmp_echo_ignore_broadcasts=1>>/etc/sysctl.conf'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42387r675334_chk'
  tag severity: 'medium'
  tag gid: 'V-239176'
  tag rid: 'SV-239176r675336_rule'
  tag stig_id: 'PHTN-67-000105'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42346r675335_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
