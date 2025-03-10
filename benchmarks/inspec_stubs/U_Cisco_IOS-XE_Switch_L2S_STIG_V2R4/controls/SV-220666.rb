control 'SV-220666' do
  title 'The Cisco switch must have all trunk links enabled statically.'
  desc 'When trunk negotiation is enabled via Dynamic Trunk Protocol (DTP), considerable time can be spent negotiating trunk settings (802.1q or ISL) when a node or interface is restored. While this negotiation is happening, traffic is dropped because the link is up from a layer 2 perspective. Packet loss can be eliminated by setting the interface statically to trunk mode, thereby avoiding dynamic trunk protocol negotiation and significantly reducing any outage when restoring a failed link or switch.'
  desc 'check', 'By default, Dynamic Trunking Protocol (DTP) is enabled on all Cisco switches. Review the switch configuration to verify that trunk links will not form trunk via negotiation as shown in the example below:

SW2#show interfaces switchport 
Name: Gi0/0
Switchport: Enabled
Administrative Mode: dynamic auto
Operational Mode: static access
Administrative Trunking Encapsulation: negotiate
Operational Trunking Encapsulation: native
Negotiation of Trunking: On

If trunk negotiation is enabled on any interface, this is a finding.'
  desc 'fix', 'Configure the switch to enable trunk links statically as shown in the configuration below:

SW2(config-if)#switchport trunk encapsulation dot1q 
SW2(config-if)#switchport mode trunk
SW2(config-if)#switchport nonegotiate'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch L2S'
  tag check_id: 'C-22381r507546_chk'
  tag severity: 'medium'
  tag gid: 'V-220666'
  tag rid: 'SV-220666r539671_rule'
  tag stig_id: 'CISC-L2-000200'
  tag gtitle: 'SRG-NET-000512-L2S-000005'
  tag fix_id: 'F-22370r507547_fix'
  tag 'documentable'
  tag legacy: ['SV-110307', 'V-101203']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
