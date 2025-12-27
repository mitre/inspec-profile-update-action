control 'SV-252588' do
  title 'IBM Aspera Faspex must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types); organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

ALGs are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. DoD continually assesses the ports, protocols, and services that can be used for network communications. Some ports, protocols or services have known exploits or security weaknesses. Network traffic using these ports, protocols, and services must be prohibited or restricted in accordance with DoD policy. The ALG is a key network element for preventing these non-compliant ports, protocols, and services from causing harm to DoD information systems.

The network ALG must be configured to prevent or restrict the use of prohibited ports, protocols, and services throughout the network by filtering the network traffic and disallowing or redirecting traffic as necessary. Default and updated policy filters from the vendors will disallow older version of protocols and applications and will address most known non-secure ports, protocols, and/or services. However, sources for further policy filters are the IAVMs and the PPSM requirements.'
  desc 'check', 'If the IBM Aspera Faspex feature of the Aspera Platform is not installed, this is Not Applicable.

The IBM Aspera Faspex is configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.

Review the port configurations of the server with the following command:

$ sudo /opt/aspera/common/asctl/asctl all:info | grep port:

http_port:         80
https_port:        443
port:               4406
base_port:         3000
http_fallback_port:8080

Ask the system administrator for the site or program PPSM CLSA. Verify the services configured for use match the PPSM Component Local Services Assessment (CLSA). 

If there are any additional ports, protocols, or services that are not included in the PPSM CLSA, this is a finding.

If there are any ports, protocols, or services that are prohibited by the PPSM CAL, this is a finding.'
  desc 'fix', 'Configure the IBM Aspera Faspex to disable functions, ports, protocols, and services that are not approved.

Use the following commands to configure only those services that are not prohibited and follow PPSM guidance for each service, protocol, and port.

For the apache instance:
$ sudo /opt/aspera/common/asctl/asctl apache:http_port <number>
$ sudo /opt/aspera/common/asctl/asctl apache:https_port <number>

For the faspex instance:
$ sudo /opt/aspera/common/asctl/asctl faspex:base_port <number>
$ sudo /opt/aspera/common/asctl/asctl faspex:http_fallback_port <number>

For the database:
$ sudo /opt/aspera/common/asctl/asctl mysql:port <number>'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56044r817932_chk'
  tag severity: 'medium'
  tag gid: 'V-252588'
  tag rid: 'SV-252588r817934_rule'
  tag stig_id: 'ASP4-FA-050240'
  tag gtitle: 'SRG-NET-000132-ALG-000087'
  tag fix_id: 'F-55994r817933_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
