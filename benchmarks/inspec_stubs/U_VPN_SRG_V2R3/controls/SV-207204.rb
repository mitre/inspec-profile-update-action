control 'SV-207204' do
  title 'The VPN Gateway must be configured to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types); organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

DoD continually assesses the ports, protocols, and services that can be used for network communications. Some protocols or services have known exploits or security weaknesses. Network traffic using these ports, protocols, and services must be prohibited or restricted in accordance with DoD policy. The PPSM CAL and vulnerability assessments provide an authoritative source for ports, protocols, and services that are unauthorized or restricted across boundaries on DoD networks.

The VPN Gateway must be configured to prevent or restrict the use of prohibited ports, protocols, and services throughout the network by filtering the network traffic and disallowing or redirecting traffic as necessary. Default and updated policy filters from the vendors will disallow older version of protocols and applications and will address most known non-secure ports, protocols, and/or services.'
  desc 'check', 'View the configured security  services.

Compare the services that are enabled, including the port, services, protocols, and functions.

If functions, ports, protocols, and services identified on the PPSM CAL are not disabled, this is a finding.'
  desc 'fix', 'Ensure functions, ports, protocols, and services identified on the PPSM CAL are not used for system services configuration.

View the configured security  services.

Compare the services that are enabled, including the port, services, protocols, and functions.

Consult the product knowledge base and configuration guides to determine the commands for disabling each port, protocols, services, or functions that is not in compliance with the PPSM CAL and vulnerability assessments.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7464r378233_chk'
  tag severity: 'medium'
  tag gid: 'V-207204'
  tag rid: 'SV-207204r608988_rule'
  tag stig_id: 'SRG-NET-000132-VPN-000450'
  tag gtitle: 'SRG-NET-000132'
  tag fix_id: 'F-7464r378234_fix'
  tag 'documentable'
  tag legacy: ['V-97079', 'SV-106217']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
