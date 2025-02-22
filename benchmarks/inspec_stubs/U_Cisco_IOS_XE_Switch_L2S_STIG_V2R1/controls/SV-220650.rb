control 'SV-220650' do
  title 'The Cisco switch must authenticate all VLAN Trunk Protocol (VTP) messages with a hash function using the most secured cryptographic algorithm available.'
  desc "VLAN Trunk Protocol (VTP) provides central management of VLAN domains, thus reducing administration in a switched network. When configuring a new VLAN on a VTP server, the VLAN is distributed through all switches in the domain. This reduces the need to configure the same VLAN everywhere. VTP pruning preserves bandwidth by preventing VLAN traffic (unknown MAC, broadcast, multicast) from being sent down trunk links when not needed, that is, there are no access switch ports in neighboring switches belonging to such VLANs. An attack can force a digest change for the VTP domain enabling a rogue device to become the VTP server, which could allow unauthorized access to previously blocked VLANs or allow the addition of unauthorized switches into the domain. Authenticating VTP messages with a cryptographic hash function can reduce the risk of the VTP domain's being compromised."
  desc 'check', 'Review the switch configuration to verify if VTP is enabled using the show vtp status command as shown in the example below:

Switch#show vtp status
VTP Version capable : 1 to 3
VTP version running : 1
VTP Domain Name : 
VTP Pruning Mode : Disabled
VTP Traps Generation : Disabled
Device ID : 5e00.0000.8000

Feature VLAN:
--------------
VTP Operating Mode : Off
Maximum VLANs supported locally : 1005
Number of existing VLANs : 5
Configuration Revision : 0
MD5 digest : 0x57 0xCD 0x40 0x65 0x63 0x59 0x47 0xBD 
 0x56 0x9D 0x4A 0x3E 0xA5 0x69 0x35 0xBC 
Switch#

If mode is set to anything other than off, verify that a password has been configured using the show vtp password command.

Note: VTP authenticates all messages using an MD5 hash that consists of the VTP version + The VTP Password + VTP Domain + VTP Configuration Revision.

If VTP is enabled on the switch and is not authenticating VTP messages with a hash function using a configured password, this is a finding.'
  desc 'fix', 'Configure the switch to authenticate all VLAN Trunk Protocol (VTP) messages with a hash function using a configured password as shown in the example below:

SW1(config)#vtp password xxxxxxxxx'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch L2S'
  tag check_id: 'C-22365r507498_chk'
  tag severity: 'medium'
  tag gid: 'V-220650'
  tag rid: 'SV-220650r539671_rule'
  tag stig_id: 'CISC-L2-000030'
  tag gtitle: 'SRG-NET-000168-L2S-000019'
  tag fix_id: 'F-22354r507499_fix'
  tag 'documentable'
  tag legacy: ['SV-110271', 'V-101167']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
