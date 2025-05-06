control 'SV-68749' do
  title 'The ALG must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types); organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

ALGs are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. DoD continually assesses the ports, protocols, and services that can be used for network communications. Some ports, protocols or services have known exploits or security weaknesses. Network traffic using these ports, protocols, and services must be prohibited or restricted in accordance with DoD policy. The ALG is a key network element for preventing these non-compliant ports, protocols, and services from causing harm to DoD information systems.

The network ALG must be configured to prevent or restrict the use of prohibited ports, protocols, and services throughout the network by filtering the network traffic and disallowing or redirecting traffic as necessary. Default and updated policy filters from the vendors will disallow older version of protocols and applications and will address most known non-secure ports, protocols, and/or services. However, sources for further policy filters are the IAVMs and the PPSM requirements.'
  desc 'check', 'View the configuration and vendor documentation of the ALG application to find the minimum ports, protocols, and services which are required for operation of the ALG.

Compare enabled ports, protocols, and/or services with the Ports, Protocol, and Service Management (PPSM) and IAVM requirements.

If ports, protocols, and/or services are not disabled or restricted as required by the PPSM, this is a finding.'
  desc 'fix', 'Disable ports, protocols, and/or services not required for operation of the ALG application.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55119r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54503'
  tag rid: 'SV-68749r1_rule'
  tag stig_id: 'SRG-NET-000132-ALG-000087'
  tag gtitle: 'SRG-NET-000132-ALG-000087'
  tag fix_id: 'F-59357r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
