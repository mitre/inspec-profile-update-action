control 'SV-21583' do
  title 'The LAN hardware supporting VVoIP services must provide physically diverse pathways for redundant links supporting command and control (C2) assured services and Fire and Emergency Services (FES) communications.'
  desc 'Voice services in support of high priority military command and control precedence must meet minimum requirements for reliability and survivability of the supporting infrastructure. Design requirements for networks supporting DoD VVoIP implementations are in the Unified Capabilities Requirements (UCR), specifying assured services supporting DoD IP based voice services. Network survivability refers to the capability of the network to maintain service continuity in the presence of faults within the network. This can be accomplished by recovering quickly from network failures quickly and maintaining the required QoS for existing services. Policy sets the minimum requirements for the availability and reliability of VVoIP systems Special-C2 users is 99.999%, C2 users is 99.997%, C2Routine only users (C2R) and non-C2 users is 99.9%.

The physical paths uplinks take should be physically diverse and optimally terminate in physically diverse locations. The best practices should support all VVoIP users but are required for Special-C2 and C2 users.'
  desc 'check', 'If the system does not support a minimum of 96 instruments, this is not applicable. Review site documentation to confirm the LAN hardware supporting VVoIP services provides physically diverse pathways for redundant links supporting C2 assured services and FES communications. The inspection of uplink pathways may require inspecting cable plant drawings or tracing the physical cable path through the building. If the LAN hardware supporting VVoIP services does not provides physically diverse pathways for redundant links supporting C2 assured services and FES communications, this is a finding.'
  desc 'fix', 'Implement and document that the LAN hardware supporting VVoIP services provides physically diverse pathways for redundant links supporting C2 assured services and FES communications. Ensure each uplink supports the full bandwidth and the appropriate routing protocol is configured for failover from one uplink to the other when a failure occurs. This applies to access layer elements connected to distribution layer elements and distribution elements connected to core layer elements. Run new cable, upgrade, or reroute as necessary.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23786r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19521'
  tag rid: 'SV-21583r2_rule'
  tag stig_id: 'VVoIP 5115'
  tag gtitle: 'VVoIP 5115'
  tag fix_id: 'F-20229r2_fix'
  tag 'documentable'
  tag severity_override_guidance: 'Reduced to CAT III when the LAN hardware does not directly support Special-C2 and C2 users.'
  tag responsibility: 'Information Assurance Officer'
end
