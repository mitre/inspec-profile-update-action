control 'SV-243166' do
  title 'The network device must be configured to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the network device must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved. Some network devices have capabilities enabled by default; if these capabilities are not necessary, they must be disabled. If a particular capability is used, it must be documented and approved.'
  desc 'check', 'Review the configuration of the network device. Verify all unnecessary and/or nonsecure functions, ports, protocols, and/or services are disabled.

If any unnecessary and/or nonsecure functions, ports, protocols, and/or services are not disabled, this is a finding.'
  desc 'fix', 'Configure the network device to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services.'
  impact 0.7
  ref 'DPMS Target Network WLAN AP-NIPR Mgmt'
  tag check_id: 'C-46441r719951_chk'
  tag severity: 'high'
  tag gid: 'V-243166'
  tag rid: 'SV-243166r719953_rule'
  tag stig_id: 'WLAN-ND-001500'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-46398r719952_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
