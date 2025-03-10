control 'SV-253131' do
  title 'TOSS must prevent IPv6 Internet Control Message Protocol (ICMP) redirect messages from being accepted.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack."
  desc 'check', 'Verify TOSS will not accept IPv6 ICMP redirect messages.

Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

Check the value of the default "accept_redirects" variables with the following command:

$ sudo sysctl net.ipv6.conf.default.accept_redirects

net.ipv6.conf.default.accept_redirects = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.'
  desc 'fix', %q(Configure TOSS to prevent IPv6 ICMP redirect messages from being accepted with the following command:

$ sudo sysctl -w net.ipv6.conf.default.accept_redirects=0

If "0" is not the system's default value then add or update the following line in the appropriate file under "/etc/sysctl.d":

net.ipv6.conf.default.accept_redirects=0)
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56584r825063_chk'
  tag severity: 'medium'
  tag gid: 'V-253131'
  tag rid: 'SV-253131r825065_rule'
  tag stig_id: 'TOSS-04-040900'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56534r825064_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
