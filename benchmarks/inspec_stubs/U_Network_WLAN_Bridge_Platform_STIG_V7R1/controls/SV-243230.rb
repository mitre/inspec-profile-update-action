control 'SV-243230' do
  title "Wireless access points and bridges must be placed in dedicated subnets outside the enclave's perimeter."
  desc 'If an adversary is able to compromise an access point or controller that is directly connected to an enclave network, the adversary can easily surveil and attack other devices from that beachhead. A defense-in-depth approach requires an additional layer of protection between the WLAN and the enclave network. This is particularly important for wireless networks, which may be vulnerable to attack from outside the physical perimeter of the facility or base given the inherent nature of radio communications to penetrate walls, fences, and other physical boundaries.

Wireless access points and bridges must not be directly connected to the enclave network. A network device must separate wireless access from other elements of the enclave network. Sites must also comply with the Network Infrastructure STIG configuration requirements for DMZ, VLAN, and VPN configurations, as applicable.

Examples of acceptable architectures include placing access points or controllers in a screened subnet (e.g., DMZ separating intranet and wireless network) or dedicated virtual LAN (VLAN) with ACLs.'
  desc 'check', "Review network architecture with the network administrator.

1. Verify compliance by inspecting the site network topology diagrams.
2. Since many network diagrams are not kept up to date, walk through the connections with the network administrator using network management tools or diagnostic commands to verify the diagrams are current.

If the site's wireless infrastructure, such as access points and bridges, is not isolated from the enclave network, this is a finding."
  desc 'fix', 'Remove wireless network devices with direct connections to an enclave network. If feasible, reconfigure network connections to isolate the WLAN infrastructure from the enclave network, separating them with a firewall or equivalent protection.'
  impact 0.5
  ref 'DPMS Target Network WLAN Bridge Platform'
  tag check_id: 'C-46505r720143_chk'
  tag severity: 'medium'
  tag gid: 'V-243230'
  tag rid: 'SV-243230r720145_rule'
  tag stig_id: 'WLAN-NW-001100'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-46462r720144_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
