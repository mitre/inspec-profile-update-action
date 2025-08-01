control 'SV-217290' do
  title 'The SUSE operating system must not respond to Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.'
  desc 'Responding to broadcast (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.'
  desc 'check', 'Verify the SUSE operating system does not accept IPv4 source-routed packets.

Check the value of the accept source route variable with the following command:

# sysctl net.ipv4.icmp_echo_ignore_broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

If the returned line does not have a value of "1" this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" (or modify the line to have the required value):

net.ipv4.icmp_echo_ignore_broadcasts = 1

Run the following command to apply this value:

# sysctl --system'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18518r370026_chk'
  tag severity: 'medium'
  tag gid: 'V-217290'
  tag rid: 'SV-217290r603262_rule'
  tag stig_id: 'SLES-12-030380'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18516r370027_fix'
  tag 'documentable'
  tag legacy: ['V-77491', 'SV-92187']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
