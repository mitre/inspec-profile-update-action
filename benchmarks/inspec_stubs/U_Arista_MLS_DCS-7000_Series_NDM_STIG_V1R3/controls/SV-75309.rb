control 'SV-75309' do
  title 'The Arista Multilayer Switch must be configured to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Determine if the network device prohibits the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.

This can be verified by reviewing the access control list configuration on the device and comparing against the PPSM CAL. The access control list configuration must deny ports, protocols, and services defined by the PPSM CAL. IP access list configuration can be viewed via the "show ip access-lists" command. To verify an interface has the appropriate access control list on it, use the "show ip access-list" summary command.

If any unnecessary or nonsecure functions are permitted, this is a finding.'
  desc 'fix', 'Configure the network device to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.

To configure an access control list, use the following commands:

configure
ip access-list [name]
10 deny [protocol] [src port] [src mask] [dst port] [dst mask] [options]
exit

To apply an access control list to an interface, use the following commands from the interface configuration mode:

ip access-group [name] [direction]'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61799r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60853'
  tag rid: 'SV-75309r1_rule'
  tag stig_id: 'AMLS-NM-000210'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-66563r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
