control 'SV-230542' do
  title 'RHEL 8 must not accept router advertisements on all IPv6 interfaces by default.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.

An illicit router advertisement message could result in a man-in-the-middle attack.'
  desc 'check', 'Verify RHEL 8 does not accept router advertisements on all IPv6 interfaces by default, unless the system is a router.

Note: If IPv6 is disabled on the system, this requirement is not applicable.

Check to see if router advertisements are not accepted by default by using the following command:

$ sudo sysctl  net.ipv6.conf.default.accept_ra

net.ipv6.conf.default.accept_ra = 0

If the "accept_ra" value is not "0" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', %q(Configure RHEL 8 to not accept router advertisements on all IPv6 interfaces by default unless the system is a router with the following commands:

$ sudo sysctl -w net.ipv6.conf.default.accept_ra=0

If "0" is not the system's default value then add or update the following lines in the appropriate file under "/etc/sysctl.d":

net.ipv6.conf.default.accept_ra=0)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-33211r568372_chk'
  tag severity: 'medium'
  tag gid: 'V-230542'
  tag rid: 'SV-230542r627750_rule'
  tag stig_id: 'RHEL-08-040262'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-33186r568373_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
