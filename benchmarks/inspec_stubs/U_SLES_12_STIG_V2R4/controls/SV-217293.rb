control 'SV-217293' do
  title 'The SUSE operating system must not allow interfaces to accept Internet Protocol version 6 (IPv6) Internet Control Message Protocol (ICMP) redirect messages by default.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack."
  desc 'check', 'Verify the SUSE operating system does not allow IPv6 ICMP redirect messages by default.

Check the value of the "default accept_redirects" variables with the following command:

# sudo sysctl net.ipv6.conf.default.accept_redirects
net.ipv6.conf.default.accept_redirects = 0

If the returned line does not have a value of "0", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to not allow IPv6 ICMP redirect messages by default. 

Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" (or modify the line to have the required value):

net.ipv6.conf.default.accept_redirects=0

Run the following command to apply this value:

# sysctl –system'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18521r370035_chk'
  tag severity: 'medium'
  tag gid: 'V-217293'
  tag rid: 'SV-217293r603262_rule'
  tag stig_id: 'SLES-12-030401'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18519r370036_fix'
  tag 'documentable'
  tag legacy: ['SV-96519', 'V-81805']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
