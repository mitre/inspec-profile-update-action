control 'SV-221879' do
  title 'The Oracle Linux operating system must ignore Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack."
  desc 'check', %q(Verify the system ignores IPv4 ICMP redirect messages.

# grep 'net.ipv4.conf.all.accept_redirects' /etc/sysctl.conf /etc/sysctl.d/*

If "net.ipv4.conf.all.accept_redirects" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of "0", this is a finding.

Check that the operating system implements the "accept_redirects" variables with the following command:

# /sbin/sysctl -a | grep 'net.ipv4.conf.all.accept_redirects'

net.ipv4.conf.all.accept_redirects = 0

If the returned line does not have a value of "0", this is a finding.)
  desc 'fix', 'Set the system to ignore IPv4 ICMP redirect messages by adding the following line to "/etc/sysctl.conf" or a configuration file in the /etc/sysctl.d/ directory (or modify the line to have the required value):

net.ipv4.conf.all.accept_redirects = 0 

Issue the following command to make the changes take effect:

# sysctl --system'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23594r419709_chk'
  tag severity: 'medium'
  tag gid: 'V-221879'
  tag rid: 'SV-221879r603260_rule'
  tag stig_id: 'OL07-00-040641'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23583r419710_fix'
  tag 'documentable'
  tag legacy: ['V-99497', 'SV-108601']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
