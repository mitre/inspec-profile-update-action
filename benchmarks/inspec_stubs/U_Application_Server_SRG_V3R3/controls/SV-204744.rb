control 'SV-204744' do
  title 'The application server must prohibit or restrict the use of nonsecure ports, protocols, modules, and/or services as defined in the PPSM CAL and vulnerability assessments.'
  desc 'Some networking protocols may not meet organizational security requirements to protect data and components.

Application servers natively host a number of various features, such as management interfaces, httpd servers and message queues. These features all run on TCPIP ports. This creates the potential that the vendor may choose to utilize port numbers or network services that have been deemed unusable by the organization. The application server must have the capability to both reconfigure and disable the assigned ports without adversely impacting application server operation capabilities. For a list of approved ports and protocols, reference the DoD ports and protocols web site at https://public.cyber.mil/connect/ppsm/'
  desc 'check', 'Review the application server documentation and deployment configuration to determine which ports and protocols are enabled.

Verify that the ports and protocols being used are not prohibited and are necessary for the operation of the application server and the hosted applications.

If any of the ports or protocols is prohibited or not necessary for the application server operation, this is a finding.'
  desc 'fix', 'Configure the application server to disable any ports or protocols that are prohibited by the PPSM CAL and vulnerability assessments.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4864r282879_chk'
  tag severity: 'medium'
  tag gid: 'V-204744'
  tag rid: 'SV-204744r508029_rule'
  tag stig_id: 'SRG-APP-000142-AS-000014'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-4864r282880_fix'
  tag 'documentable'
  tag legacy: ['V-57501', 'SV-71777']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
