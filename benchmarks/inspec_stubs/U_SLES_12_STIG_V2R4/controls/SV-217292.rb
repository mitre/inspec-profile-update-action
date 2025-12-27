control 'SV-217292' do
  title 'The SUSE operating system must not allow interfaces to accept Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages by default.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack."
  desc 'check', 'Verify the SUSE operating system ignores IPv4 ICMP redirect messages.

Check the value of the "accept_redirects" variables with the following command:

# sysctl net.ipv4.conf.default.accept_redirects
net.ipv4.conf.default.accept_redirects = 0

If the returned line does not have a value of "0" this is a finding.'
  desc 'fix', 'Configure the SUSE operating system ignores IPv4 ICMP redirect messages by adding the following line to "/etc/sysctl.conf" (or modify the line to have the required value):

net.ipv4.conf.default.accept_redirects = 0

Run the following command to apply this value:

# sysctl --system'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18520r370032_chk'
  tag severity: 'medium'
  tag gid: 'V-217292'
  tag rid: 'SV-217292r603262_rule'
  tag stig_id: 'SLES-12-030400'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18518r370033_fix'
  tag 'documentable'
  tag legacy: ['SV-92191', 'V-77495']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
