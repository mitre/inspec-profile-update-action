control 'SV-55756' do
  title 'An enclave supporting an IP-based VTC system that must communicate across an IP WAN must implement a VTC/VVoIP-aware firewall or H.460-based firewall traversal solution at its boundary with the WAN.'
  desc 'To support a VTC session through a standard non H.323 aware firewall, the administrator must open a wide range (from 16000 to 65000) of UDP ports. If the VTU only connects with one other endpoint CODEC or MCU, this port opening can be limited to the IP address of the other end. While a hole has been opened in the firewall, the risk is somewhat mitigated by the address restriction. However, if a VTC call can come from any endpoint, with any IP address, then the hole resulting from opening the UDP ports to a large range of IP addresses negates the effectiveness of the firewall. To mitigate this issue, an H.460 border controller is required rather than opening all UDP ports to all or many IP addresses. This device effectively limits all of the UDP and TCP ports required to support H.323 VTC sessions to a very small number (3-7), the connections through which are initiated from within the enclave thus requiring little or no firewall reconfiguration to accommodate.

H.460 is a set of extensions to the ITU H.323 standard that includes methods to traverse firewalls.  In order for a video conference to take place across a secure firewall using H.460, a server or appliance using H.460 must be available and reachable by video conferencing endpoints. Video conference endpoints need to register with an H.460 server and in order to do this they must be enabled for this by their respective manufacturers.

This requirement results in a CAT III finding in the event this requirement cannot be met and IP ports are statically opened on a standard firewall to accommodate VTC traffic such that the IP ports are restricted by the internal IP address(es) of the internal CODEC(s) and the external address(es) of a central MCU or a limited set of remote endpoints using an any-any statement.  This CAT III can be eliminated in the event these ports are not statically opened, but are manually opened and closed by the firewall administrator for the duration of VTC sessions. This CAT III can also be eliminated in the event the inbound permit statements are restricted to a limited range of UDP ports and external IP addresses, while routing/outbound permit statements forces all outbound VTC traffic to these external addresses.'
  desc 'check', 'Review system documentation and verify that a VTC/VVoIP-aware firewall or H.460-based firewall traversal solution has been implemented at the enclave boundary. If this does not exist, verify the following: 
• The enclave firewall allows VTC traffic only to the internal IP address(es) of the internal CODEC(s) and the external address(es) of a central MCU or a limited set of remote endpoints. 
• The inbound permit statements are restricted to a limited range of UDP ports and external IP addresses while routing/outbound permit statements force all outbound VTC traffic to these external addresses.
• These UDP ports are not statically opened, but are manually opened and closed by the firewall administrator for the duration of VTC sessions. 

If there is not a VTC/VVoIP-aware firewall or H.460-based firewall traversal solution implemented at the enclave boundary and no other measures have been taken, this is a CAT I finding.

If there is not a VTC/VVoIP-aware firewall or H.460-based firewall traversal solution implemented at the enclave boundary, and the firewall is configured to allow VTC traffic only to the internal IP address(es) of the internal CODEC(s) and the external address(es) of a central MCU or a limited set of remote endpoints and the inbound permit statements are restricted to a limited range of UDP ports, this is a CAT III finding. If the firewall allows the VTC traffic only during VTC sessions, then this is no longer a finding.'
  desc 'fix', 'Obtain and implement a VTC/VVoIP-aware firewall or H.460-based firewall traversal solution at the enclave boundary. If this is not possible, configure the existing firewall to allow VTC traffic only to the internal IP address(es) of the internal CODEC(s) and the external address(es) of a central MCU or a limited set of remote endpoints. If possible, reconfigure the firewall to close VTC ports between sessions.'
  impact 0.7
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49184r4_chk'
  tag severity: 'high'
  tag gid: 'V-43027'
  tag rid: 'SV-55756r1_rule'
  tag stig_id: 'RTS-VTC 6000'
  tag gtitle: 'RTS-VTC 6000 [IP]'
  tag fix_id: 'F-48611r2_fix'
  tag 'documentable'
  tag severity_override_guidance: 'This can be downgraded from a CAT I to a CAT III if this requirement cannot be met and IP ports are statically opened on a standard firewall to accommodate VTC traffic such that the IP ports are restricted by the internal IP address(es) of the internal CODEC(s) and the external address(es) of a central MCU or a limited set of remote endpoints using an any-any statement. This CAT III can be eliminated in the event these ports are not statically opened, but are manually opened and closed by the firewall administrator for the duration of VTC sessions. This CAT III can also be eliminated in the event the inbound permit statements are restricted to a limited range of UDP ports and external IP addresses, while routing/outbound permit statements force all outbound VTC traffic to these external addresses.'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'DCPP-1, EBBD-2'
end
