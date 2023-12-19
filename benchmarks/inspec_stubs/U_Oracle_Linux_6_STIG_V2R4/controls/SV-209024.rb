control 'SV-209024' do
  title 'The DHCP client must be disabled if not needed.'
  desc 'DHCP relies on trusting the local network. If the local network is not trusted, then it should not be used. However, the automatic configuration provided by DHCP is commonly used and the alternative, manual configuration, presents an unacceptable burden in many circumstances.'
  desc 'check', %q(To verify that DHCP is not being used, examine the following file for each interface. 

# /etc/sysconfig/network-scripts/ifcfg-[IFACE]

If there is any network interface without a associated "ifcfg" file, this is a finding.

Look for the following:

BOOTPROTO=none

Also verify the following, substituting the appropriate values based on your site's addressing scheme:

NETMASK=[local LAN netmask]
IPADDR=[assigned IP address]
GATEWAY=[local LAN default gateway]

If it does not, this is a finding.)
  desc 'fix', %q(For each interface [IFACE] on the system (e.g. eth0), edit "/etc/sysconfig/network-scripts/ifcfg-[IFACE]" and make the following changes. 

Correct the BOOTPROTO line to read:

BOOTPROTO=none

Add or correct the following lines, substituting the appropriate values based on your site's addressing scheme:

NETMASK=[local LAN netmask]
IPADDR=[assigned IP address]
GATEWAY=[local LAN default gateway])
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9277r357857_chk'
  tag severity: 'medium'
  tag gid: 'V-209024'
  tag rid: 'SV-209024r603263_rule'
  tag stig_id: 'OL6-00-000292'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9277r357858_fix'
  tag 'documentable'
  tag legacy: ['V-50889', 'SV-65095']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
