control 'SV-237037' do
  title 'The A10 Networks ADC must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types); organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

The device must be configured to prevent or restrict the use of prohibited ports, protocols, and services throughout the network by filtering the network traffic and disallowing or redirecting traffic as necessary. Default and updated policy filters from the vendors will disallow older version of protocols and applications and will address most known non-secure ports, protocols, and/or services. However, sources for further policy filters are the IAVMs and the PPSM requirements.'
  desc 'check', 'Review the list of authorized applications, endpoints, services, and protocols that have been added to the PPSM database.

Review the configured servers, service groups, and virtual servers. 

The following command shows information for SLB servers:
show slb server

The following command shows information for service groups (multiple servers):
show slb service-group

The following command shows information for virtual servers (the services visible to outside hosts):
show slb virtual-server

If any of the servers, service groups, or virtual servers allows traffic that is prohibited by the PPSM CAL, this is a finding.'
  desc 'fix', 'Do not configure a server, service group, or virtual server for any port, protocol, or service that is prohibited by the PPSM CAL.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40256r639556_chk'
  tag severity: 'medium'
  tag gid: 'V-237037'
  tag rid: 'SV-237037r639558_rule'
  tag stig_id: 'AADC-AG-000036'
  tag gtitle: 'SRG-NET-000132-ALG-000087'
  tag fix_id: 'F-40219r639557_fix'
  tag 'documentable'
  tag legacy: ['SV-82457', 'V-67967']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
