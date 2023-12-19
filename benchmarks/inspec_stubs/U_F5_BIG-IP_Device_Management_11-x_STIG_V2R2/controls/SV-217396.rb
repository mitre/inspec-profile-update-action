control 'SV-217396' do
  title 'The BIG-IP appliance must be configured to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management (PPSM) Category Assurance List (CAL) and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Verify the BIG-IP appliance prohibits the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments. 

Navigate to the BIG-IP System manager >> System >> Services.

Verify no unauthorized services are configured or running.

If any unnecessary or nonsecure functions are permitted, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18621r290742_chk'
  tag severity: 'medium'
  tag gid: 'V-217396'
  tag rid: 'SV-217396r879588_rule'
  tag stig_id: 'F5BI-DM-000093'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-18619r290743_fix'
  tag 'documentable'
  tag legacy: ['SV-74569', 'V-60139']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
