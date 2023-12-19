control 'SV-252941' do
  title 'TOSS must not be performing packet forwarding unless the system is a router.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.'
  desc 'check', 'Verify TOSS is not performing packet forwarding unless the system is a router. If the system is a router (sometimes called a gateway) this requirement is Not Applicable.

Note: If either IPv4 or IPv6 is disabled on the system, this requirement only applies to the active internet protocol version.

Check to see if IP forwarding is enabled using the following commands:

$ sudo sysctl net.ipv4.ip_forward

net.ipv4.ip_forward = 0

$ sudo sysctl net.ipv6.conf.all.forwarding

net.ipv6.conf.all.forwarding = 0

If IP forwarding value is not "0" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', %q(Configure TOSS to not allow packet forwarding, unless the system is a router with the following commands:

$ sudo sysctl -w net.ipv4.ip_forward=0

$ sudo sysctl -w net.ipv6.conf.all.forwarding=0

If "0" is not the system's default value then add or update the following lines in the appropriate file under "/etc/sysctl.d":

net.ipv4.ip_forward=0

net.ipv6.conf.all.forwarding=0)
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56394r824145_chk'
  tag severity: 'medium'
  tag gid: 'V-252941'
  tag rid: 'SV-252941r824147_rule'
  tag stig_id: 'TOSS-04-010390'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56344r824146_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
