control 'SV-218042' do
  title 'The DHCP client must be disabled if not needed.'
  desc 'DHCP relies on trusting the local network. If the local network is not trusted, then it should not be used. However, the automatic configuration provided by DHCP is commonly used and the alternative, manual configuration, presents an unacceptable burden in many circumstances.'
  desc 'check', 'IIf DHCP is required by the organization, this is Not Applicable.

For each interface [IFACE] on the system (e.g. eth0), verify that DHCP is not being used:

Note: This requirement does not apply to the local loopback interface.

# cat /etc/sysconfig/network-scripts/ifcfg-[IFACE] | grep -i “bootproto” | grep –v “#”

BOOTPROTO=none

If no output is returned this is a finding.

If BOOTPROTO is not set to ”none”, this is a finding.'
  desc 'fix', %q(For each interface [IFACE] on the system (e.g. eth0), edit "/etc/sysconfig/network-scripts/ifcfg-[IFACE]" and make the following changes. 

Correct the BOOTPROTO line to read:

BOOTPROTO=none


Add or correct the following lines, substituting the appropriate values based on your site's addressing scheme:

NETMASK=[local LAN netmask]
IPADDR=[assigned IP address]
GATEWAY=[local LAN default gateway])
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19523r462409_chk'
  tag severity: 'medium'
  tag gid: 'V-218042'
  tag rid: 'SV-218042r603264_rule'
  tag stig_id: 'RHEL-06-000292'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-19521r462410_fix'
  tag 'documentable'
  tag legacy: ['V-38679', 'SV-50480']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
