control 'SV-204625' do
  title 'The Red Hat Enterprise Linux operating system must not be performing packet forwarding unless the system is a router.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.'
  desc 'check', 'Verify the system is not performing packet forwarding, unless the system is a router.

     # grep -r net.ipv4.ip_forward /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
     net.ipv4.ip_forward = 0

If "net.ipv4.ip_forward" is not configured in the /etc/sysctl.conf file or in any of the other sysctl.d directories, is commented out, or does not have a value of "0", this is a finding.

Check that the operating system does not implement IP forwarding using the following command:

     # /sbin/sysctl -a | grep net.ipv4.ip_forward
     net.ipv4.ip_forward = 0

If IP forwarding value is "1" and the system is hosting any application, database, or web servers, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" or a configuration file in the /etc/sysctl.d/ directory (or modify the line to have the required value):

     net.ipv4.ip_forward = 0

Issue the following command to make the changes take effect:

     # sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4749r880822_chk'
  tag severity: 'medium'
  tag gid: 'V-204625'
  tag rid: 'SV-204625r880824_rule'
  tag stig_id: 'RHEL-07-040740'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-4749r880823_fix'
  tag 'documentable'
  tag legacy: ['SV-86933', 'V-72309']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
