control 'SRG-NET-000383-CLD-000200_rule' do
  title 'For IaaS/PaaS, the Mission Owner must configure an Intrusion Detection and Prevention System (IDPS) to protect DOD VMs, services, and applications.'
  desc 'Network environments and applications installed using an I/PaaS cloud service offering where the Mission Owner has control over the environment must comply with DOD network infrastructure and host policies. Putting an application in the cloud does not take care of all security responsibilities.

Without coordinated reporting between cloud service environments used for DOD mission, it is not possible to identify the true scale and possible target of an attack. An IDPS protects Mission Owner enclaves and applications hosted in an off-premise cloud service offering and may be deployed within the cloud service environment, cloud access point, or supporting Core Data Center (CDC). Additionally, an IDPS facilitates the reporting of incidents and aid in the coordination of response actions between all stakeholders of the cloud service offering and/or mission owner applications.

The Mission Owner and/or their Cybersecurity Service Provider (CSSP) must be able to monitor the virtual network boundary. For dedicated infrastructure with a DODIN connection (Levels 4–6), implement an IDPS that monitors and works with the virtual security infrastructure (e.g., firewall, routing tables, WAF, etc.) to protect traffic flow inbound and outbound to/from the virtual network to the DODIN connection.'
  desc 'check', 'If this is a SaaS, this is not applicable.

Review SLA and architecture documentation. Verify the virtual IDPS is in place by inspecting the architecture diagrams. Verify that it is placed to monitor and protect the IaaS, PaaS, and interconnected host VMs.

Verify a secure (encrypted) connection exists between the virtual IDPS capabilities and the CSSP responsible for the mission system/application.

If the Mission Owner has not configured the IaaS or PaaS IDPS to monitor and protect the IaaS and interconnected VMs, this is a finding.'
  desc 'fix', 'This applies to all Impact Levels.
FedRAMP Moderate, High.

Configure a virtual IDPS to monitor and protect the DOD VMs, services, and applications.'
  impact 0.7
  tag check_id: 'C-SRG-NET-000383-CLD-000200_chk'
  tag severity: 'high'
  tag gid: 'SRG-NET-000383-CLD-000200'
  tag rid: 'SRG-NET-000383-CLD-000200_rule'
  tag stig_id: 'SRG-NET-000383-CLD-000200'
  tag gtitle: 'SRG-NET-000383-CLD-000200'
  tag fix_id: 'F-SRG-NET-000383-CLD-000200_fix'
  tag 'documentable'
  tag cci: ['CCI-002656']
  tag nist: ['SI-4 (1)']
end
