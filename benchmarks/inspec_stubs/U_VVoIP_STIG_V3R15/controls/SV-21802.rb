control 'SV-21802' do
  title 'The data network boundary must block all traffic destined to or sourced from VVoIP VLAN IP address space and VLANs except specifically permitted media and signaling traffic.'
  desc 'The typical data firewall does not adequately protect the enclave when permitting VVoIP to traverse the boundary. Furthermore, a data firewall breaks VVoIP call completion when implementing NAT. NAT is no longer a security requirement. To properly protect the enclave when implementing VVoIP across the boundary, there are a specific set of processes and protections required, referred to as the VVoIP firewall function. These are separate from the data firewall processes and protections. The data firewall function plays a part in the protection of the VVoIP sub-enclave within the LAN, while the VVoIP firewall function protects the entire enclave while permitting the VVoIP system to function properly.'
  desc 'check', 'Review site documentation to confirm the data network boundary protects the VVoIP VLANS by blocking all but specifically permitted traffic destined to or sourced from the Voice VLAN IP address space and VLANs. The data firewall configuration must block all traffic destined to or sourced from VVoIP VLANs and address space, except as follows:
- VVoIP signaling, media, and registration protocols to and from a remote endpoint via a properly authenticated VPN tunnel. When an SBC is not in use, traffic is blocked from the data VLANs and routed to the VVoIP VLANs. When an SBC is in use, session traffic must be routed through the SBC.
- Management traffic to and from a remote NOC destined for the VVoIP management VLAN address space. In this case, the data firewall and IDS inspects this traffic before it is routed to the VVoIP management VLAN. Such routing must block all traffic from the data VLAN, data subnets, and the general data network management VLANs.
- Protected LSC to LSC communications clustered across the WAN.
- The enclave is connected to a limited access or closed WAN, and the WAN has a dedicated address space for VVoIP. In this case, the VVoIP traffic may pass through the data firewall when the permitted traffic is limited to/from the dedicated WAN address space and routed to the internal VVoIP VLANs.

If the network perimeter does not protect the VVoIP VLANS by blocking all but specifically permitted traffic destined to or sourced from the Voice VLAN IP address space and VLANs, this is a finding.'
  desc 'fix', 'Implement the network perimeter to protect the VVoIP VLANS by blocking all but specifically permitted traffic destined to or sourced from the Voice VLAN IP address space and VLANs.'
  impact 0.7
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-24027r4_chk'
  tag severity: 'high'
  tag gid: 'V-19661'
  tag rid: 'SV-21802r5_rule'
  tag stig_id: 'VVoIP 6200'
  tag gtitle: 'VVoIP 6200'
  tag fix_id: 'F-20366r4_fix'
  tag 'documentable'
end
