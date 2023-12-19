control 'SV-79703' do
  title 'The DataPower Gateway must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types); organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

ALGs are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. DoD continually assesses the ports, protocols, and services that can be used for network communications. Some ports, protocols or services have known exploits or security weaknesses. Network traffic using these ports, protocols, and services must be prohibited or restricted in accordance with DoD policy. The ALG is a key network element for preventing these non-compliant ports, protocols, and services from causing harm to DoD information systems.

The network ALG must be configured to prevent or restrict the use of prohibited ports, protocols, and services throughout the network by filtering the network traffic and disallowing or redirecting traffic as necessary. Default and updated policy filters from the vendors will disallow older version of protocols and applications and will address most known non-secure ports, protocols, and/or services. However, sources for further policy filters are the IAVMs and the PPSM requirements.'
  desc 'check', 'Review the list of authorized applications, services, and protocols that has been added to the PPSM database.

Privileged Account User logon to the WebGUI >> Log on to the Default domain >>
Click Status >> Main >> Active Services >> Click Show All Domains.

If any of the Active Services allows traffic that is prohibited by the PPSM CAL, this is a finding.'
  desc 'fix', 'Review the PPSM CAL before configuring services on the DataPower Gateway. This device will either be placed in the enclave DMZ or on a private network; this must be taken into account.
Configure only those services that are not prohibited and follow PPSM guidance for each service, protocol, and port.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65841r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65213'
  tag rid: 'SV-79703r1_rule'
  tag stig_id: 'WSDP-AG-000036'
  tag gtitle: 'SRG-NET-000132-ALG-000087'
  tag fix_id: 'F-71153r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
