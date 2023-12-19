control 'SV-21576' do
  title 'The LAN hardware supporting VVoIP services must provide redundancy to support command and control (C2) assured services and Fire and Emergency Services (FES) communications.'
  desc 'Voice services in support of high priority military command and control precedence must meet minimum requirements for reliability and survivability of the supporting infrastructure. Design requirements for networks supporting DoD VVoIP implementations are in the UCR, specifying assured services supporting DoD IP based voice services. The UCR defines LAN design requirements for redundancy of equipment and interconnections, minimum requirements for bandwidth, specifications for backup power, and the maximum number of endpoints tolerable by a single point of failure. Policy sets the minimum requirements for the availability and reliability of VVoIP systems Special-C2 users is 99.999%, C2 users is 99.997%, C2Routine only users (C2R) and non-C2 users is 99.9%.

Similar availability and reliability through redundancy is needed to support routine user FES life-safety and security related communications.'
  desc 'check', 'If the system does not support a minimum of 96 instruments, this is not applicable. Review site documentation to confirm the LAN hardware supporting VVoIP services provide redundancy to support C2 assured services and FES communications. 
Ensure the LAN hardware is redundant as follows: 
- Dual Power Supplies - each platform must have a minimum of two power supplies and the loss of a single power supply shall not cause any loss of functions within the chassis.
- Dual Processors (Control Supervisors) - each chassis shall support dual control processors and failure of any one processor shall not cause any loss of functions within the chassis.
- Termination Sparing - each chassis shall support a (N + 1) sparing capability minimally for available Ethernet modules used to terminate to an IP subscriber.
- Protocol Redundancy - each routing device shall support protocols allowing for dynamic rerouting.
- Backplane Redundancy – each switching platform shall support a redundant (1 + 1) switching fabric or backplane and the second fabric’s backplane shall be in active standby so that failure of the first shall not cause loss of ongoing events within the switch. Alternately, a secondary product may be added to provide redundancy to the primary product when redundant protocols are implemented such that the failover over to the secondary product must not result in any lost calls.
If the LAN hardware supporting VVoIP services does not provide redundancy to support C2 assured services and FES communications, this is a finding.'
  desc 'fix', 'Implement and document that the LAN hardware supporting VVoIP services provides redundancy to support C2 assured services and FES communications. Mandatory redundancy includes the following: 
- Dual Power Supplies - each platform must have a minimum of two power supplies and the loss of a single power supply shall not cause any loss of functions within the chassis.
- Dual Processors (Control Supervisors) - each chassis shall support dual control processors and failure of any one processor shall not cause any loss of functions within the chassis.
- Termination Sparing - each chassis shall support a (N + 1) sparing capability minimally for available Ethernet modules used to terminate to an IP subscriber.
- Protocol Redundancy - each routing device shall support protocols allowing for dynamic rerouting.
- Backplane Redundancy – each switching platform shall support a redundant (1 + 1) switching fabric or backplane and the second fabric’s backplane shall be in active standby so that failure of the first shall not cause loss of ongoing events within the switch. Alternately, a secondary product may be added to provide redundancy to the primary product when redundant protocols are implemented such that the failover over to the secondary product must not result in any lost calls.
Redundancy may not be required for VVoIP systems supporting less than 96 users but best practice is to provide redundancy or maintain spares such that service can be restored in a timely manner in the event of a failure.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23782r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19514'
  tag rid: 'SV-21576r2_rule'
  tag stig_id: 'VVoIP 5110'
  tag gtitle: 'VVoIP 5110'
  tag fix_id: 'F-20226r2_fix'
  tag 'documentable'
  tag severity_override_guidance: 'Reduced to CAT III when the LAN hardware does not directly support Special-C2 and C2 users.'
  tag responsibility: 'Information Assurance Officer'
end
