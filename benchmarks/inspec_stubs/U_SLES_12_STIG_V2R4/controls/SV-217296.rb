control 'SV-217296' do
  title 'The SUSE operating system must not be performing Internet Protocol version 4 (IPv4) packet forwarding unless the system is a router.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.'
  desc 'check', 'Verify the SUSE operating system is not performing IPv4packet forwarding, unless the system is a router.

Check to see if IPv4 forwarding is enabled using the following command:

> sysctl net.ipv4.ip_forward
net.ipv4.ip_forward = 0

If the network parameter "ipv4.ip_forward" is not equal to "0" or nothing is returned, this is a finding.'
  desc 'fix', %q(Configure the SUSE operating system to not performing IPv4 packet forwarding by running the following command as an administrator:

> sudo sysctl -w net.ipv4.ip_forward=0

If "0" is not the system's default value, add or update the following line in "/etc/sysctl.d/99-stig.conf":

> sudo sh -c 'echo "net.ipv4.ip_forward=0" >> /etc/sysctl.d/99-stig.conf'

> sudo sysctl --system)
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18524r646765_chk'
  tag severity: 'medium'
  tag gid: 'V-217296'
  tag rid: 'SV-217296r646767_rule'
  tag stig_id: 'SLES-12-030430'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18522r646766_fix'
  tag 'documentable'
  tag legacy: ['V-77501', 'SV-92197']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
