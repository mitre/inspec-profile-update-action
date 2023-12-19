control 'SV-23730' do
  title 'Network elements configuration supporting VoIP services must interconnect redundant uplinks following physically diverse paths to physically diverse network elements in the layer above with support for the full bandwidth handled by the network element using routing protocols facilitating failover.'
  desc 'Policy sets the minimum requirements for the availability and reliability of VoIP systems and the supporting LAN with emphasis on C2 communications. The high availability and reliability required for Special-C2 and C2 users is achieved in part by interconnecting LAN network elements with redundant uplinks via geographically diverse paths. The core layer connects to the distribution layer below it, which then connects to the access layer below it.

Voice services in support of high-priority military command and control precedence must meet minimum requirements for reliability and survivability of the supporting infrastructure. Design requirements for networks supporting DoD VVoIP implementations are in the Unified Capabilities Requirements (UCR), specifying assured services supporting DoD IP-based voice services. Network survivability refers to the capability of the network to maintain service continuity in the presence of faults within the network. This can be accomplished by recovering quickly from network failures quickly and maintaining the required QoS for existing services.'
  desc 'check', 'If the network elements do not support a minimum of 96 instruments, this is not applicable. If the network elements are deployed in a LAN that covers an extremely small geographical area in a single physical location, this is not applicable. To meet the applicability for a geographical area, most users must be within 100 meters cabling distance of the core equipment, and the access layer switches must not be separated from the single central core location. 

Confirm the network elements configuration supporting VoIP services to interconnect redundant uplinks following physically diverse paths to physically diverse network elements in the layer above with support for the full bandwidth handled by the network element using routing protocols facilitating failover. 

If the network elements supporting VoIP services do not connect redundant uplinks following physically diverse paths to physically diverse network elements in the layer above, this is a finding. If the network elements configuration does not support the full bandwidth handled by the network element using routing protocols facilitating failover, this is a finding.'
  desc 'fix', 'Configure the network elements supporting VoIP services to interconnect redundant uplinks following physically diverse paths to physically diverse network elements in the layer above. Configure the network elements to support the full bandwidth handled by the network element using routing protocols facilitating failover.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-25773r2_chk'
  tag severity: 'medium'
  tag gid: 'V-21518'
  tag rid: 'SV-23730r3_rule'
  tag stig_id: 'VVoIP 5116'
  tag gtitle: 'VVoIP 5116'
  tag fix_id: 'F-22310r2_fix'
  tag 'documentable'
  tag severity_override_guidance: 'Reduced to CAT III when the network elements do not directly support Special-C2 and C2 users.'
end
