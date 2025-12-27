control 'SV-202049' do
  title 'The network device must be configured to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved. Some network devices have capabilities enabled by default; if these capabilities are not necessary, they must be disabled. If a particular capability is used, then it must be documented and approved.'
  desc 'check', 'Determine if the network device prohibits the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services. If any unnecessary or nonsecure functions are permitted, this is a finding.'
  desc 'fix', 'Configure the network device to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services.'
  impact 0.7
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2175r381752_chk'
  tag severity: 'high'
  tag gid: 'V-202049'
  tag rid: 'SV-202049r395856_rule'
  tag stig_id: 'SRG-APP-000142-NDM-000245'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-2176r381753_fix'
  tag 'documentable'
  tag legacy: ['SV-69347', 'V-55101']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
