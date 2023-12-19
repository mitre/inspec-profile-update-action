control 'SRG-NET-000205-CLD-000030_rule' do
  title 'The IaaS/PaaS must implement a security stack that restricts traffic flow inbound and outbound between the IaaS and the BCAP or ICAP connection.'
  desc 'DOD users on the internet may first connect into their assigned DISN Virtual Private Network (VPN) network before accessing DOD private applications. The virtual environment may be composed of an array of cloud service offerings from a particular CSP. The DISN security architecture provides connectivity to the cloud service environment to the users. The architecture mitigates potential damages to the DISN and will provide the ability to detect and prevent an attack before reaching the DISN.

Note: Off-premise CSP infrastructure having a Level 2 PA is directly connected to the internet, all traffic to and from a Level 2 CSO serving Level 2 missions and their mission virtual networks will connect via the internet.

CSP Infrastructure (dedicated to DOD) located inside the B/C/P/S “fence line” (i.e., on-premises) connects via an ICAP. The architecture of ICAPs may vary and may leverage existing capabilities such as the IA stack protecting a DOD Data center today or perhaps a Joint Regional Security Stack (JRSS). On the other hand, an ICAP may have special capabilities to support specific missions, CSP types (commercial or DOD), or cloud services.

CSP infrastructure (shared with non-DOD or dedicated to DOD) located outside the B/C/P/S fence line that connects to the DODIN/NIPRNet does so via one or more BCAPs. The BCAP terminates dedicated circuits and VPN connections originating within the CSP’s network infrastructure and/or Mission Owner’s virtual networks. All connections between a CSP’s network infrastructure or Mission Owner’s virtual networks that is accessed via or from the NIPRNet/SIPRNet must connect to the DODIN via a BCAP. For dedicated infrastructure with a DODIN connection (Levels 4–6), the Mission Owner will ensure a virtual security stack is configured IAW DODI 8551.'
  desc 'check', 'If this is an Impact Level 2 IaaS/PaaS implementation, this requirement is not applicable. 

Review the architecture for the IaaS.

Verify that for dedicated infrastructure mission Impact Levels 4–5 the IaaS implements a security stack that restricts traffic flow inbound and outbound between the IaaS/PaaS and the BCAP or ICAP connection.

For IaaS Levels 4–5 if the IaaS does not implement a security stack that restricts traffic flow inbound and outbound between the IaaS/PaaS and the BCAP or ICAP connection, this is a finding.'
  desc 'fix', 'FedRAMP Moderate, High.

For dedicated infrastructure with an ICAP/BCAP connection (Levels 4–5 and on Premise Impact Level 2), ensure that the IaaS/PaaS implements a security stack that restricts traffic flow inbound and outbound between the IaaS/PaaS and the BCAP or ICAP connection.'
  impact 0.7
  tag check_id: 'C-SRG-NET-000205-CLD-000030_chk'
  tag severity: 'high'
  tag gid: 'SRG-NET-000205-CLD-000030'
  tag rid: 'SRG-NET-000205-CLD-000030_rule'
  tag stig_id: 'SRG-NET-000205-CLD-000030'
  tag gtitle: 'SRG-NET-000205-CLD-000030'
  tag fix_id: 'F-SRG-NET-000205-CLD-000030_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
