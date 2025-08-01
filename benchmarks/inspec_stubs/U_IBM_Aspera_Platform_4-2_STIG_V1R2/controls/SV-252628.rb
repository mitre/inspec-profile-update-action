control 'SV-252628' do
  title 'The IBM Aspera High-Speed Transfer Server must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types); organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

ALGs are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. DoD continually assesses the ports, protocols, and services that can be used for network communications. Some ports, protocols or services have known exploits or security weaknesses. Network traffic using these ports, protocols, and services must be prohibited or restricted in accordance with DoD policy. The ALG is a key network element for preventing these non-compliant ports, protocols, and services from causing harm to DoD information systems.

The network ALG must be configured to prevent or restrict the use of prohibited ports, protocols, and services throughout the network by filtering the network traffic and disallowing or redirecting traffic as necessary. Default and updated policy filters from the vendors will disallow older version of protocols and applications and will address most known non-secure ports, protocols, and/or services. However, sources for further policy filters are the IAVMs and the PPSM requirements.'
  desc 'check', 'The IBM Aspera High-Speed Transfer Server is configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.

Review the port configurations of the HSTS with the following command:

$ sudo /opt/aspera/bin/asuserdata -a | grep port:

transfer_protocol_options_bind_udp_port: "33001"
    trunk_mcast_port: "0"
    trunk_mcast_port: "0"
port: "4406"
port: "40001"
mgmt_port: "0"
http_port: "8080"
https_port: "8443"
http_port: "9091"
https_port: "9092"
ssh_port: "33001"
db_port: "31415"
scalekv_sstore_port: "31415"
scalekv_baseport: "43001"
aej_port: "0"
rproxy_rules_rule_proxy_port: "33001"
initd_db_port: "31416"
wss_port: "9093"

Ask the system administrator for the site or program PPSM CLSA. Verify the services configured for use match the PPSM Component Local Services Assessment (CLSA). 

If there are any additional ports, protocols, or services that are not included in the PPSM CLSA, this is a finding.

If there are any ports, protocols, or services that are prohibited by the PPSM CAL, this is a finding.'
  desc 'fix', 'Configure the IBM Aspera High-Speed Transfer Server to disable functions, ports, protocols, and services that are not approved.

Edit the /opt/aspera/etc/aspera.conf file and configure only those services that are not prohibited and follow PPSM guidance for each service, protocol, and port.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56084r818052_chk'
  tag severity: 'medium'
  tag gid: 'V-252628'
  tag rid: 'SV-252628r818054_rule'
  tag stig_id: 'ASP4-TS-020110'
  tag gtitle: 'SRG-NET-000132-ALG-000087'
  tag fix_id: 'F-56034r818053_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
