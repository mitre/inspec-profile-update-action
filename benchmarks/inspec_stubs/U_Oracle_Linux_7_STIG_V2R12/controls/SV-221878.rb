control 'SV-221878' do
  title 'The Oracle Linux operating system must prevent Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages from being accepted.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack."
  desc 'check', 'Verify the system will not accept IPv4 ICMP redirect messages.

     # grep -r net.ipv4.conf.default.accept_redirects /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null

If "net.ipv4.conf.default.accept_redirects" is not configured in the /etc/sysctl.conf file or in any of the other sysctl.d directories, is commented out, or does not have a value of "0", this is a finding.

Check that the operating system implements the value of the "accept_redirects" variables with the following command:

     # /sbin/sysctl -a | grep net.ipv4.conf.default.accept_redirects
     net.ipv4.conf.default.accept_redirects = 0

If the returned line does not have a value of "0", this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Set the system to not accept IPv4 ICMP redirect messages by adding the following line to "/etc/sysctl.conf" or a configuration file in the /etc/sysctl.d/ directory (or modify the line to have the required value):

     net.ipv4.conf.default.accept_redirects = 0 

Issue the following command to make the changes take effect:

     # sysctl --system'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23593r880649_chk'
  tag severity: 'medium'
  tag gid: 'V-221878'
  tag rid: 'SV-221878r880651_rule'
  tag stig_id: 'OL07-00-040640'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23582r880650_fix'
  tag 'documentable'
  tag legacy: ['V-99495', 'SV-108599']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
