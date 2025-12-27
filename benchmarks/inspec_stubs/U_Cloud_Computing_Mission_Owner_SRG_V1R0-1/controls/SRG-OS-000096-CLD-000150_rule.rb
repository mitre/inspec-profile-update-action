control 'SRG-OS-000096-CLD-000150_rule' do
  title 'The Mission Owner must configure the IaaS/PaaS to prohibit or restrict the use of functions, ports, protocols, and/or services.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), Mission Owners must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Ports, Protocols, and Services Management (PPSM) when implementing and operating their systems/applications in an IaaS/PaaS CSO. (incomplete sentence)

SaaS solutions: Register the Protocols and Services along with their related UDP/TCP IP Ports used by the SaaS service that will traverse the DISN in the DOD PPSM registry. This includes all user and management plane traffic for Levels 4, 5, and 6 as well as management plane traffic for Level 2 if managed/monitored from within a DOD network.'
  desc 'check', 'If this is an Impact Level 2 CSO, this is not a finding.

For dedicated infrastructure with a DODIN connection (Levels 4–6), review the architecture diagrams. Verify that the virtual firewall ACLs that restrict traffic flow inbound and outbound to/from the cloud service to the DODIN connection comply with the boundary requirements. Verify all traffic from the CSP enclave and other sources are blocked by these methods.

If the cloud service offering is not configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments, this is a finding.'
  desc 'fix', 'Applies to Impact Level 4/5/6.
FedRAMP Moderate, High.

For dedicated infrastructure with a DODIN connection (Levels 4–6), configure the IaaS/PaaS virtual firewall that restricts traffic flow inbound and outbound to/from the cloud service to the DODIN connection and block all traffic from all other sources.'
  impact 0.5
  tag check_id: 'C-SRG-OS-000096-CLD-000150_chk'
  tag severity: 'medium'
  tag gid: 'SRG-OS-000096-CLD-000150'
  tag rid: 'SRG-OS-000096-CLD-000150_rule'
  tag stig_id: 'SRG-OS-000096-CLD-000150'
  tag gtitle: 'SRG-OS-000096-CLD-000150'
  tag fix_id: 'F-SRG-OS-000096-CLD-000150_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
