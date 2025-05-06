control 'SV-222519' do
  title 'The application must be configured to use only functions, ports, and protocols permitted to it in the PPSM CAL.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services; however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Review the application documentation and configuration.

Interview the application administrator.

Identify the network ports and protocols that are utilized by the application.

Using a combination of relevant OS commands and application configuration utilities identify the TCP/IP port numbers the application is configured to utilize and is utilizing.

Review the PPSM web page at:

http://www.disa.mil/Network-Services/Enterprise-Connections/PPSM

Review the PPSM Category Assurance List (CAL) directly at the following link: 

https://disa.deps.mil/ext/cop/iase/ppsm/Pages/cal.aspx

Verify the ports used by the application are approved by the PPSM CAL.

If the ports are not approved by the PPSM CAL, this is a finding.'
  desc 'fix', 'Configure the application to utilize application ports approved by the PPSM CAL.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24189r493465_chk'
  tag severity: 'medium'
  tag gid: 'V-222519'
  tag rid: 'SV-222519r508029_rule'
  tag stig_id: 'APSC-DV-001510'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-24178r493466_fix'
  tag 'documentable'
  tag legacy: ['V-69521', 'SV-84143']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
