control 'SV-77319' do
  title 'The Riverbed Optimization System (RiOS) must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types); organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

ALGs are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. DoD continually assesses the ports, protocols, and services that can be used for network communications. Some ports, protocols or services have known exploits or security weaknesses. Network traffic using these ports, protocols, and services must be prohibited or restricted in accordance with DoD policy. Riverbed Optimization System (RiOS) is a key network element for preventing these non-compliant ports, protocols, and services from causing harm to DoD information systems.

The network ALG must be configured to prevent or restrict the use of prohibited ports, protocols, and services throughout the network by filtering the network traffic and disallowing or redirecting traffic as necessary. Default and updated policy filters from the vendors will disallow older version of protocols and applications and will address most known non-secure ports, protocols, and/or services. However, sources for further policy filters are the IAVMs and the PPSM requirements.'
  desc 'check', 'Verify that the Riverbed Optimization System (RiOS) is configured to disable unrelated or unneeded application proxy services.

Obtain documentation for which applications are approved/disapproved for optimization by the organization.

Navigate to the device Management Console
Navigate to Optimize >> Optimization

Verify that the approved or disapproved applications are enabled or disabled according to organization requirements.

If optimization features are not enabled or disabled according to the organizations requirements, this is a finding.'
  desc 'fix', 'Check to see if services other than the authorized services are enabled for optimization.

Obtain documentation for which applications are approved/disapproved for optimization by the organization.

Navigate to the device Management Console
Navigate to Optimize >> Optimization

Set the approved or disapproved applications to enabled or disabled according to organization requirements.'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 ALG'
  tag check_id: 'C-63623r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62829'
  tag rid: 'SV-77319r1_rule'
  tag stig_id: 'RICX-AG-000088'
  tag gtitle: 'SRG-NET-000132-ALG-000087'
  tag fix_id: 'F-68747r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
