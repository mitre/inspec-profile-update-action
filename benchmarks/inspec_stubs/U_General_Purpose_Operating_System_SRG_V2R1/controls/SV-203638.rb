control 'SV-203638' do
  title 'The operating system must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Verify the operating system is configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3763r557640_chk'
  tag severity: 'medium'
  tag gid: 'V-203638'
  tag rid: 'SV-203638r557642_rule'
  tag stig_id: 'SRG-OS-000096-GPOS-00050'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-3763r557641_fix'
  tag 'documentable'
  tag legacy: ['V-56751', 'SV-71011']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
