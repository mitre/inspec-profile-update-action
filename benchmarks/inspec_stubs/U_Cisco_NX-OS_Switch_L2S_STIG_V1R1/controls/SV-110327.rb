control 'SV-110327' do
  title 'The Cisco switch must authenticate all VLAN Trunk Protocol (VTP) messages with a hash function using the most secured cryptographic algorithm available.'
  desc "VLAN Trunk Protocol (VTP) provides central management of VLAN domains, thus reducing administration in a switched network. When configuring a new VLAN on a VTP server, the VLAN is distributed through all switches in the domain. This reduces the need to configure the same VLAN everywhere. VTP pruning preserves bandwidth by preventing VLAN traffic (unknown MAC, broadcast, multicast) from being sent down trunk links when not needed, that is, there are no access switch ports in neighboring switches belonging to such VLANs. An attack can force a digest change for the VTP domain enabling a rogue device to become the VTP server, which could allow unauthorized access to previously blocked VLANs or allow the addition of unauthorized switches into the domain. Authenticating VTP messages with a cryptographic hash function can reduce the risk of the VTP domain's being compromised."
  desc 'check', 'Review the switch configuration to verify if VTP is enabled.

Step 1: Enter the show feature command to determine if vtp is enabled.

Step 2: Enter the show vtp status command to determine operating mode.

SW1# show vtp status
VTP Status Information
----------------------
VTP Version : 2 (capable)
Configuration Revision : 0
Maximum VLANs supported locally : 1005
Number of existing VLANs : 5
VTP Operating Mode : Transparent
VTP Domain Name : XXXXX
VTP Pruning Mode : Disabled (Operationally Disabled)
VTP V2 Mode : Disabled
VTP Traps Generation : Disabled
MD5 Digest : 0x0C 0x5E 0xC3 0x74 0x3F 0xB0 0x2F 0x49

If mode is set to anything other than off or transparent, verify that a password has been configured using the show vtp password command.

Note: VTP authenticates all messages using an MD5 hash that consists of the VTP version + The VTP Password + VTP Domain + VTP Configuration Revision.

If VTP is enabled on the switch and is not authenticating VTP messages with a hash function using a configured password, this is a finding.'
  desc 'fix', 'Configure the switch to authenticate all VLAN Trunk Protocol (VTP) messages with a hash function using a configured password as shown in the example below:

SW1(config)# vtp password xxxxxxxxx'
  impact 0.5
  ref 'DPMS Target NX-OS L2 Switch'
  tag check_id: 'C-100103r1_chk'
  tag severity: 'medium'
  tag gid: 'V-101223'
  tag rid: 'SV-110327r1_rule'
  tag stig_id: 'CISC-L2-000030'
  tag gtitle: 'SRG-NET-000168-L2S-000019'
  tag fix_id: 'F-106927r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
