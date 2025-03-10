control 'SV-21494' do
  title 'The local VVoIP system must have the capability to place intra-site and local phone calls when network connectivity is severed from the remote centrally-located session controller.'
  desc 'Voice phone services are critical to the effective operation of a business, an office, or in support or control of a DoD mission. It is critical that phone service is available in the event of an emergency situation such as a security breach or life safety event. The ability of maintaining the ability to place calls to emergency services must be maintained. DoD voice networks are designed to be extremely reliable and provide continuity of operations (COOP) support. However, the potential exists that a site may become severed from the DoD network. Some site’s DoD VoIP phone systems are implemented without a local session controller. The session controller may be located remotely and serve several sites by providing long local service. This implementation scenario provides for central management of the overall phone system, saves in initial implementation cost, and saves in operating costs. As such this scenario has many benefits. Unfortunately, the reality of this implementation is that in order to place a call between two endpoints within the local site or to place a call via the local commercial service connection, the initiating end instrument has to send its signal messages to the remote session controller over the DISN WAN connection, then the session controller has to signal the called instrument or media gateway over the same WAN connection. Several messages are sent (back and forth) over the WAN connection before the two local endpoints can send their media streams directly between themselves. While the need to signal over the WAN connection can cause longer call setup time which can be extended if there is congestion in the network, no call can be placed anywhere from the local site if it is cut off from its session controller. Based on this fact, and in support of maintaining viable local voice services in the event the site is cut off from its remote session controller, each physical site must maintain minimal local call control as a backup so that local intra-site and local commercial network calls can be placed. While this works to maintain local emergency service availability for security and life safety emergencies, it also provides the capability to make calls between DoD sites using the commercial network.'
  desc 'check', 'Review site documentation to confirm the local VVoIP system has the capability to place intra-site and local phone calls when network connectivity is severed from the remote centrally located session controller. 

If the local VVoIP system does not have the capability to place intra-site and local phone calls when network connectivity is severed, this is a finding.

Reliance on GFE or personal cell phones does not meet this requirement because signal strength and reliability are reduced inside buildings and cell phones are not permitted in most DoD facilities.

The minimum capability for placement of line-side precedence calls is dependent upon the C2 requirements of the site and must be determined in conjunction with the local command authority. To satisfy this requirement the minimum requirement is the maintenance of ROUTINE call placement capabilities.'
  desc 'fix', 'Implement and document the local VVoIP system with the capability to place intra-site and local phone calls when network connectivity is severed. The minimum capability for placement of line-side precedence calls is dependent upon the C2 requirements of the site and must be determined in conjunction with the local command authority. To satisfy this requirement the minimum requirement is the maintenance of ROUTINE call placement capabilities.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23709r3_chk'
  tag severity: 'medium'
  tag gid: 'V-19443'
  tag rid: 'SV-21494r3_rule'
  tag stig_id: 'VVoIP 1215'
  tag gtitle: 'VVoIP 1215'
  tag fix_id: 'F-20187r3_fix'
  tag 'documentable'
  tag severity_override_guidance: 'Reduced to no finding when the site has a separate commercial phone system (dedicated PBX or discrete instruments) available for areas with long local service.

Reduced to no finding when the site has with a separate DoD phone system (PBX or discrete instruments) with a network path that is geographically separate from the system under evaluation available for areas with long local service.

Reduced to no finding when the site has backup VVoIP call control to maintain local internal and commercial service if network connectivity is severed from the remote centrally located session controller.'
end
