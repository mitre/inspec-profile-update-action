control 'SV-207385' do
  title 'The VMM must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on VMMs.

VMMs are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the VMM must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Verify the VMM is configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.

If it is not, this is a finding.'
  desc 'fix', 'Configure the VMM to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7642r365565_chk'
  tag severity: 'medium'
  tag gid: 'V-207385'
  tag rid: 'SV-207385r378844_rule'
  tag stig_id: 'SRG-OS-000096-VMM-000490'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-7642r365566_fix'
  tag 'documentable'
  tag legacy: ['V-56961', 'SV-71221']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
