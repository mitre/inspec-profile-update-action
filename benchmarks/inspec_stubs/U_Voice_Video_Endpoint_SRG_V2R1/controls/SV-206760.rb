control 'SV-206760' do
  title 'The Voice Video Endpoint must only use ports, protocols, and services allowed per the Ports, Protocols, and Services Management (PPSM) Category Assurance List (CAL) and Vulnerability Assessments (VAs).'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems. Voice video endpoints are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component but doing so increases risk compared to limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the network element must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues. The current Category Assurance List (CAL) and Vulnerability Assessments (VA) listings for ports, protocols, and services are available on the DISA Information Assurance Support Environment (IASE) website for Ports, Protocols, and Services Management (PPSM) at https://cyber.mil/ppsm.'
  desc 'check', 'Verify the Voice Video Endpoint only uses ports, protocols, and services allowed per the PPSM CAL and VAs. If the Voice Video Endpoint uses ports, protocols, and services not allowed per the PPSM CAL and VAs, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint to only use ports, protocols, and services allowed per the PPSM CAL and VAs.'
  impact 0.7
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7016r459019_chk'
  tag severity: 'high'
  tag gid: 'V-206760'
  tag rid: 'SV-206760r604140_rule'
  tag stig_id: 'SRG-NET-000132-VVEP-00059'
  tag gtitle: 'SRG-NET-000132'
  tag fix_id: 'F-7016r459020_fix'
  tag 'documentable'
  tag legacy: ['SV-81289', 'V-66799']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
