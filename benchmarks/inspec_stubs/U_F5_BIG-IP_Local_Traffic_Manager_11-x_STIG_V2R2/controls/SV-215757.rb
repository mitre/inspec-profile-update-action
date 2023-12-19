control 'SV-215757' do
  title 'The BIG-IP Core implementation must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocol, and Service Management (PPSM) Category Assurance List (CAL) and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types); organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

ALGs are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. DoD continually assesses the ports, protocols, and services that can be used for network communications. Some ports, protocols, or services have known exploits or security weaknesses. Network traffic using these ports, protocols, and services must be prohibited or restricted in accordance with DoD policy. The ALG is a key network element for preventing these non-compliant ports, protocols, and services from causing harm to DoD information systems.

The network ALG must be configured to prevent or restrict the use of prohibited ports, protocols, and services throughout the network by filtering the network traffic and disallowing or redirecting traffic as necessary. Default and updated policy filters from the vendors will disallow older versions of protocols and applications and will address most known non-secure ports, protocols, and/or services. However, sources for further policy filters are the IAVMs and the PPSM requirements.'
  desc 'check', 'Review the BIG-IP Core to verify the minimum ports, protocols, and services that are required for operation of the BIG-IP Core are configured.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Compare enabled ports, protocols, and/or services in the "Service Port" column with the PPSM and IAVM requirements.

If the BIG-IP Core is configured with ports, protocols, and/or services that are not required for operations or restricted by the PPSM, this is a finding.'
  desc 'fix', 'Configure Virtual Servers in the BIG-IP LTM module to use only ports, protocols, and/or services required for operation of the BIG-IP Core.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16949r291084_chk'
  tag severity: 'medium'
  tag gid: 'V-215757'
  tag rid: 'SV-215757r557356_rule'
  tag stig_id: 'F5BI-LT-000071'
  tag gtitle: 'SRG-NET-000132-ALG-000087'
  tag fix_id: 'F-16947r291085_fix'
  tag 'documentable'
  tag legacy: ['V-60295', 'SV-74725']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
