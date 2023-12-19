control 'SV-237623' do
  title 'The SUSE operating system must not be performing Internet Protocol version 6 (IPv6) packet forwarding by default unless the system is a router.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.'
  desc 'check', 'Verify the SUSE operating system is not performing IPv6 packet forwarding by default, unless the system is a router.

Check to see if IPv6 forwarding is disabled by default using the following command:

> sudo sysctl net.ipv6.conf.default.forwarding
net.ipv6.conf.default.forwarding = 0

If the network parameter "ipv6.conf.default.forwarding" is not equal to "0" or nothing is returned, this is a finding.'
  desc 'fix', %q(Configure the SUSE operating system to not performing IPv6 packet forwarding by default by running the following command as an administrator:

> sudo sysctl -w net.ipv6.conf.default.forwarding=0

If "0" is not the system's default value, add or update the following line in "/etc/sysctl.d/99-stig.conf":

> sudo sh -c 'echo "net.ipv6.conf.default.forwarding=0" >> /etc/sysctl.d/99-stig.conf'

> sudo sysctl --system)
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-40842r646830_chk'
  tag severity: 'medium'
  tag gid: 'V-237623'
  tag rid: 'SV-237623r646832_rule'
  tag stig_id: 'SLES-12-030365'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-40805r646831_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
