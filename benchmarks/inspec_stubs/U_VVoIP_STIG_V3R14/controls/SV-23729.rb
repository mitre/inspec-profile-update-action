control 'SV-23729' do
  title 'Network elements configuration supporting VoIP services must provide redundancy supporting command and control (C2) assured services and Fire and Emergency Services (FES) communications.'
  desc 'Policy sets the minimum requirements for the availability and reliability of VVoIP systems and the supporting LAN with emphasis on C2 communications. The high availability and reliability required for Special-C2 and C2 users is achieved in part by redundancy within the LAN network elements. Policy sets the minimum requirements for the availability and reliability of VVoIP systems Special-C2 users at 99.999 percent, C2 users at 99.997 percent, and C2 Routine only users (C2R) and non-C2 users at 99.9 percent. 

Voice services in support of high-priority military command and control precedence must meet minimum requirements for reliability and survivability of the supporting infrastructure. Design requirements for networks supporting DoD VVoIP implementations are in the Unified Capabilities Requirements (UCR), specifying assured services supporting DoD IP-based voice services. Network survivability refers to the capability of the network to maintain service continuity in the presence of faults within the network. This can be accomplished by recovering from network failures quickly and maintaining the required QoS for existing services.'
  desc 'check', 'If the network elements do not support a minimum of 96 instruments, this is not applicable. Review the network elements configuration supporting VoIP services to provide redundancy supporting C2 assured services and FES communications. Visually confirm the routing and switching network devices are redundant as follows:
- Dual Power Supplies - Each platform must have a minimum of two power supplies and the loss of a single power supply shall not cause any loss of functions within the chassis.
- Dual Processors (Control Supervisors) - Each chassis shall support dual control processors and failure of any one processor shall not cause any loss of functions within the chassis.
- Termination Sparing - Each chassis shall support a (N + 1) sparing capability minimally for available Ethernet modules used to terminate to an IP subscriber.
- Protocol Redundancy - Each routing device shall support protocols allowing for dynamic rerouting.
- Backplane Redundancy – each switching platform shall support a redundant (1 + 1) switching fabric or backplane and the second fabric’s backplane shall be in active standby so that failure of the first shall not cause loss of ongoing events within the switch. Alternately, a secondary product may be added to provide redundancy to the primary product when redundant protocols are implemented such that the failover over to the secondary product must not result in any lost calls.

Additionally, test the redundancy failover capability. While it is possible to unplug power cords and take other measures to test the failover capabilities, this is not recommended and must not be done in a production network unless scheduled for off duty hours. 

If required failover capability is tested and fails, this is a finding. If the network elements configuration supporting VoIP services does not provide the redundancy conditions above to support C2 assured services and FES communications, this is a finding.'
  desc 'fix', 'Configure the network elements supporting VoIP services to provide redundancy supporting C2 assured services and FES communications. Ensure the routing and switching network devices have redundant capability and configured to implement as follows:
- Dual Power Supplies - each platform must have a minimum of two power supplies and the loss of a single power supply shall not cause any loss of functions within the chassis.
- Dual Processors (Control Supervisors) - each chassis shall support dual control processors and failure of any one processor shall not cause any loss of functions within the chassis.
- Termination Sparing - each chassis shall support a (N + 1) sparing capability minimally for available Ethernet modules used to terminate to an IP subscriber.
- Protocol Redundancy - each routing device shall support protocols allowing for dynamic rerouting.
- Backplane Redundancy - Each switching platform shall support a redundant (1 + 1) switching fabric or backplane and the second fabric’s backplane shall be in active standby so that failure of the first shall not cause loss of ongoing events within the switch. Alternately, a secondary product may be added to provide redundancy to the primary product when redundant protocols are implemented such that the failover over to the secondary product must not result in any lost calls.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-25770r2_chk'
  tag severity: 'medium'
  tag gid: 'V-21517'
  tag rid: 'SV-23729r3_rule'
  tag stig_id: 'VVoIP 5111'
  tag gtitle: 'VVoIP 5111'
  tag fix_id: 'F-22309r2_fix'
  tag 'documentable'
  tag severity_override_guidance: 'Reduced to CAT III when the network elements do not directly support Special-C2 and C2 users.'
end
