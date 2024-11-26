control 'SV-8710' do
  title 'MGCP and/or H.248 (MEGACO) is not restricted/controlled on the LAN and/or protected on the WAN using encryption OR MGCP and/or H.248 (MEGACO) packets are not authenticated or filtered by source IP address.'
  desc 'Media Gateway Control Protocol (MGCP) is a protocol that is used between Media Gateway Controllers (MGCs), Media Gateways (MGs), and other MGs to exchange sensitive gateway status and zone information as well as establish sessions via the MG. MGCP is a clear text human readable protocol. This information is critical in the setup and completion of voice calls from one VoIP zone to another VoIP zone or more typically from a VoIP zone to a TDM zone. If this information is poisoned or if collected and used by an unauthorized unscrupulous individual, the effects to the VoIP environment could be detrimental. Denial-of-service or fraudulent system use are only two of the potential compromises. As such, MGCP messages must be protected from eavesdropping, man in the middle, and replay attacks. To protect MGCP, Request for Comment (RFC) 2705 which defines MGCP outlines and recommends the use of IPsec for encryption and authentication between gateways. This recommendation primarily applies to the use of MGCP across unprotected WANs like the Internet. This extends to use on NIPRNet as well. A follow-on protocol defined jointly by the IETF in RFC 3435 and the ITU-T in Recommendation H.248.1 is MEGACO/H.248 which provides the same general functionality as MGCP. RFC 3435 also requires that H.248 packets be authenticated and/or encrypted using IPsec. Unfortunately there is not widespread support by MGCs and MGs for IPsec protection and therefore we must rely on external IPsec VPNs when traversing the WAN. When confined within the LAN, we can protect MGCP in a number of ways without IPsec.'
  desc 'check', 'Request the SA demonstrate the measures used to protect MGCP or MEGACO/H.248 signaling on MGs, MGCs, and other devices such as end instruments if they use MGCP or MEGACO/H.248, by providing configuration details.

When the MGCP or MEGACO/H.248 is used to control Media Gateways (MGs) or other devices (e.g., endpoints), the following must be addressed: 
 - The LSC/MGC and MG are located in the same protected LSC VLAN and ACLs are established on all VLAN egress points to block the MGCP or MEGACO/H.248 from exiting the VLAN; OR 
 - The LSC/MGC and MG are located in adjacent protected VLANs and ACLs are established to permit MGCP or MEGACO/H.248 between the LSC/MGC and MG but block the MGCP or MEGACO/H.248 from exiting these VLANs; AND 
 - In the event MGCP or MEGACO/H.248 is used to control a MG or a distributed set of MGs across a WAN, ensure an encrypted VPN is used to protect the MGCP traffic. 
 - Additionally, ensure the source of MGCP or MEGACO/H.248 packets is authenticated to originate from a valid source and/or minimally filter acceptance on source IP address.

If the MGCP and H.248 (MEGACO) are not restricted on the LAN, and protected on the WAN using encryption, OR MGCP and H.248 (MEGACO) packets are not authenticated or filtered by source IP address, this is a finding.'
  desc 'fix', 'When the MGCP or MEGACO/H.248 is used to control Media Gateways (MGs) or other devices (e.g., endpoints), the following must be addressed: 
 - The LSC/MGC and MG are located in the same protected LSC VLAN and ACLs are established on all VLAN egress points to block the MGCP or MEGACO/H.248 from exiting the VLAN; OR 
 - The LSC/MGC and MG are located in adjacent protected VLANs and ACLs are established to permit MGCP or MEGACO/H.248 between the LSC/MGC and MG but block the MGCP or MEGACO/H.248 from exiting these VLANs; AND 
 - In the event MGCP or MEGACO/H.248 is used to control a MG or a distributed set of MGs across a WAN, ensure an encrypted VPN is used to protect the MGCP traffic. 
 - Additionally, ensure the source of MGCP or MEGACO/H.248 packets is authenticated to originate from a valid source and/or minimally filter acceptance on source IP address.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23704r2_chk'
  tag severity: 'medium'
  tag gid: 'V-8224'
  tag rid: 'SV-8710r2_rule'
  tag stig_id: 'VVoIP 1405'
  tag gtitle: 'VVoIP 1405'
  tag fix_id: 'F-20185r2_fix'
  tag 'documentable'
end
