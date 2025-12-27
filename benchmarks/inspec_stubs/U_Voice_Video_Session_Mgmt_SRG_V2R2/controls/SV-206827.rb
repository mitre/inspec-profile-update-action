control 'SV-206827' do
  title 'The Voice Video Session Manager must only use of ports, protocols, and services allowed per the Ports, Protocols, and Services Management (PPSM) Category Assurance List (CAL) and Vulnerability Assessments (VAs).'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Network elements are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the network element must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Requires further clarification from NIST.'
  desc 'check', 'Verify the Voice Video Session Manager only uses ports, protocols, and services allowed per the PPSM CAL and VAs.

If the Verify the Voice Video Session Manager uses ports, protocols, and services other than those permitted by the PPSM CAL and VAs, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to only use of ports, protocols, and services allowed per the PPSM CAL and VAs.'
  impact 0.7
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7082r364670_chk'
  tag severity: 'high'
  tag gid: 'V-206827'
  tag rid: 'SV-206827r508661_rule'
  tag stig_id: 'SRG-NET-000131-VVSM-00049'
  tag gtitle: 'SRG-NET-000131'
  tag fix_id: 'F-7082r364671_fix'
  tag 'documentable'
  tag legacy: ['V-62089', 'SV-76579']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
