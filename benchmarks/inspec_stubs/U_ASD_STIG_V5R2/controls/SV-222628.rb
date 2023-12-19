control 'SV-222628' do
  title 'New IP addresses, data services, and associated ports used by the application must be submitted to the appropriate approving authority for the organization, which in turn will be submitted through the DoD Ports, Protocols, and Services Management (DoD PPSM)'
  desc 'Failure to comply with DoD Ports, Protocols, and Services (PPS) Vulnerability Analysis and associated PPS mitigations may result in compromise of enclave boundary protections and/or functionality of the application.'
  desc 'check', 'All application ports, protocols, and services needed for application operation need to be in compliance with the DoD Ports and Protocols guidance.

Check:

http://iase.disa.mil/ppsm/Pages/index.aspx

to verify the ports, protocols, and services are in compliance with the PPS CAL.

Check all necessary ports and protocols needed for application operation (only those accessed from outside the local enclave) are checked against the DoD Ports and Protocols guidance to ensure compliance.

Identify the ports needed for the application:

- Look at System Security Plan/Accreditation documentation
- Ask System Administrator
- Go to Network Administrator
- Go to Network Reviewer
- If a network scan is available, use it
- Use netstat/task manager
- Check /etc./services

If the application is not in compliance with DoD Ports and Protocols guidance, this is a finding.'
  desc 'fix', 'Verify the accreditation documentation lists all interfaces and the ports, protocols, and services used.

Verify that all ports, protocols, and services are used in accordance with the DoD PPSM.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-36255r602328_chk'
  tag severity: 'medium'
  tag gid: 'V-222628'
  tag rid: 'SV-222628r864412_rule'
  tag stig_id: 'APSC-DV-002980'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-36219r602329_fix'
  tag 'documentable'
  tag legacy: ['SV-84935', 'V-70313']
  tag cci: ['CCI-000388']
  tag nist: ['CM-7 (3)']
end
