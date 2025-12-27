control 'SV-253134' do
  title 'TOSS must use reverse path filtering on all IPv4 interfaces.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Enabling reverse path filtering drops packets with source addresses that are not routable. There is not an equivalent filter for IPv6 traffic.'
  desc 'check', 'Verify TOSS uses reverse path filtering on all IPv4 interfaces with the following commands:

$ sudo sysctl net.ipv4.conf.all.rp_filter

net.ipv4.conf.all.rp_filter = 1

If the returned line does not have a value of "1", or a line is not returned, this is a finding.'
  desc 'fix', 'Configure TOSS to use reverse path filtering on all IPv4 interfaces by adding the following line to a file in the "/etc/sysctl.d" directory:

net.ipv4.conf.all.rp_filter = 1

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56587r825072_chk'
  tag severity: 'medium'
  tag gid: 'V-253134'
  tag rid: 'SV-253134r825074_rule'
  tag stig_id: 'TOSS-04-040930'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56537r825073_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
