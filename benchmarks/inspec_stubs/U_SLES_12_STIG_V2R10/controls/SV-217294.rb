control 'SV-217294' do
  title 'The SUSE operating system must not allow interfaces to send Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages by default.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table, possibly revealing portions of the network topology."
  desc 'check', 'Verify the SUSE operating system does not allow interfaces to perform IPv4 ICMP redirects by default.

Check the value of the "default send_redirects" variables with the following command:

# sysctl net.ipv4.conf.default.send_redirects
net.ipv4.conf.default.send_redirects = 0

If the returned line does not have a value of "0” this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to not allow interfaces to perform IPv4 ICMP redirects by default. 

Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" (or modify the line to have the required value):

net.ipv4.conf.default.send_redirects=0

Run the following command to apply this value:

# sysctl --system'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18522r370038_chk'
  tag severity: 'medium'
  tag gid: 'V-217294'
  tag rid: 'SV-217294r603262_rule'
  tag stig_id: 'SLES-12-030410'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18520r370039_fix'
  tag 'documentable'
  tag legacy: ['V-77497', 'SV-92193']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
