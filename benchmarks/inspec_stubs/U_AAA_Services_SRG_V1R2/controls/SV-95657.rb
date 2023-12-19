control 'SV-95657' do
  title 'AAA Services must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services; however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Review the AAA Services configuration to ascertain if it prohibits or restricts the use of organization-defined functions, ports, protocols, and/or services. Further determine if the use is as defined in the PPSM CAL and vulnerability assessments.

If AAA Services are not configured in accordance with the PPSM CAL and vulnerability assessments, this is a finding.'
  desc 'fix', 'Configure AAA Services to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80685r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80947'
  tag rid: 'SV-95657r1_rule'
  tag stig_id: 'SRG-APP-000142-AAA-000680'
  tag gtitle: 'SRG-APP-000142-AAA-000680'
  tag fix_id: 'F-87803r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
