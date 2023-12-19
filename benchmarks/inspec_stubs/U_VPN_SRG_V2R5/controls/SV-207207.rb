control 'SV-207207' do
  title 'For site-to-site VPN implementations, the  L2TP protocol must be blocked or denied at the security boundary with the private network so unencrypted L2TP packets cannot traverse into the private network of the enclave.'
  desc "Unlike GRE (a simple encapsulating header) L2TP is a full-fledged communications protocol with control channel, data channels, and a robust command structure. In addition to PPP, other link layer types (called pseudowires) can be and are defined for delivery in L2TP by separate RFC documents. Further complexity is created by the capability to define vender-specific parameters beyond those defined in the L2TP specifications.

The endpoint devices of an L2TP connection can be an L2TP Access Concentrator (LAC) in which case it inputs/outputs the layer 2 protocol to/from the L2TP tunnel. Otherwise, it is an L2TP Network Server (LNS), in which case it inputs/outputs the layer 3 (IP) protocol to/from the L2TP tunnel. The specifications describe three reference models: LAC-LNS, LAC-LAC, and LNS-LNS, the first of which is the most common case. The LAC-LNS model allows a remote access user to reach his home network or ISP from a remote location. The remote access user connects to  a LAC device which tunnels his connection home to an awaiting LNS. The LAC could also be located on the remote user's laptop, which connects to an LNS at home using some generic internet connection. The other reference models may be used for more obscure scenarios.

Although the L2TP protocol does not contain encryption capability, it can be operated over IPsec, which would provide authentication and confidentiality. A remote user in the LAC-LNS model would most likely obtain a dynamically assigned IP address from the home network to ultimately use through the tunnel back to the home network. Secondly, the outer IP source address used to send the L2TP tunnel packet to the home network is likely to be unknown or highly variable. Thirdly, since the LNS provides the remote user with a dynamic IP address to use, the firewall at the home network would have to be dynamically updated to accept this address in conjunction with the outer tunnel address. Finally, there is also the issue of authentication of the remote user prior to divulging an acceptable IP address. Because of all of these complications, the strict filtering rules applied to the IP-in-IP and GRE tunneling cases will likely not be possible in the L2TP scenario.

In addition to the difficulty of enforcing addresses and endpoints (as explained above), the L2TP protocol itself is a security concern if allowed through a security boundary. In particular:

1) L2TP potentially allows link layer protocols to be delivered from afar. These protocols were intended for link-local scope only, are less defended, and not as well-known,
2) The L2TP tunnels can carry IP packets that are very difficult to see and filter because of the additional layer 2 overhead,
3) L2TP is highly complex and variable (vender-specific variability) and therefore would be a viable target that is difficult to defend. It is better left outside of the main firewall where less damage occurs if the L2TP-processing node is compromised,
4) Filtering cannot be used to detect and prevent other unintended layer 2 protocols from being tunneled. The strength of the application layer code would have to be relied on to achieve this task,
5) Regardless of whether the L2TP is handled inside or outside of the main network, a secondary layer of IP filtering is required; therefore bringing it inside does not save resources.

Therefore, it is not recommended to allow unencrypted L2TP packets across the security boundary into the network's protected areas. Reference the Backbone Transport STIG for additional L2TP guidance and use."
  desc 'check', 'If L2TP communications protocol is not used, this is not applicable.

Verify the VPN Gateway or another network element (e.g., firewall) is configure to block or deny L2TP packets with a destination address within the private network of the enclave.

If L2TP communications are  allowed to cross the security boundary into the private network of the enclave, this is a finding.'
  desc 'fix', 'If L2TP is used for encapsulation, configure the VPN Gateway or other network element to block or deny this communications protocol unencrypted L2TP packets across the security boundary and into the private network of the enclave.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7467r378242_chk'
  tag severity: 'medium'
  tag gid: 'V-207207'
  tag rid: 'SV-207207r608988_rule'
  tag stig_id: 'SRG-NET-000132-VPN-000480'
  tag gtitle: 'SRG-NET-000132'
  tag fix_id: 'F-7467r378243_fix'
  tag 'documentable'
  tag legacy: ['V-97085', 'SV-106223']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
