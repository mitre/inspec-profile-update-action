control 'SV-217291' do
  title 'The SUSE operating system must prevent Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages from being accepted.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack."
  desc 'check', 'Verify the SUSE operating system does not accept ICMP redirect messages.

Check the value of the "net.ipv4.conf.all.accept_redirects" variable with the following command:

# sysctl net.ipv4.conf.all.accept_redirects
net.ipv4.conf.all.accept_redirects =0

If the returned line does not have a value of "0" this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" (or modify the line to have the required value):

net.ipv4.conf.all.accept_redirects =0

Run the following command to apply this value:

# sysctl --system'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18519r370029_chk'
  tag severity: 'medium'
  tag gid: 'V-217291'
  tag rid: 'SV-217291r603262_rule'
  tag stig_id: 'SLES-12-030390'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18517r370030_fix'
  tag 'documentable'
  tag legacy: ['V-77493', 'SV-92189']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
