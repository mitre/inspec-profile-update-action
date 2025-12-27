control 'SV-221874' do
  title 'The Oracle Linux operating system must use a reverse-path filter for IPv4 network traffic when possible on all interfaces.'
  desc 'Enabling reverse path filtering drops packets with invalid source addresses received on the interface.  It should not be used on systems which are routers for complicated networks, but is helpful for end hosts and routers serving small networks.'
  desc 'check', 'Verify the system uses a reverse-path filter for IPv4:

# grep net.ipv4.conf.all.rp_filter /etc/sysctl.conf /etc/sysctl.d/*
net.ipv4.conf.all.rp_filter = 1

If "net.ipv4.conf.all.rp_filter" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of "1", this is a finding.

Check that the operating system implements the accept source route variable with the following command:

# /sbin/sysctl -a | grep net.ipv4.conf.all.rp_filter
net.ipv4.conf.all.rp_filter = 1

If the returned line does not have a value of "1", this is a finding.'
  desc 'fix', 'Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" or a configuration file in the /etc/sysctl.d/ directory (or modify the line to have the required value):

net.ipv4.conf.all.rp_filter = 1 

Issue the following command to make the changes take effect:

# sysctl --system'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23589r419694_chk'
  tag severity: 'medium'
  tag gid: 'V-221874'
  tag rid: 'SV-221874r603260_rule'
  tag stig_id: 'OL07-00-040611'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23578r419695_fix'
  tag 'documentable'
  tag legacy: ['V-99487', 'SV-108591']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
