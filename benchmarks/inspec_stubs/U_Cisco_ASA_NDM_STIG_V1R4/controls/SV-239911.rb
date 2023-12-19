control 'SV-239911' do
  title 'The Cisco ASA must be configured to prohibit the use of all unnecessary and/or non-secure functions, ports, protocols, and/or services.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved. Some network devices have capabilities enabled by default; if these capabilities are not necessary, they must be disabled. If a particular capability is used, then it must be documented and approved.'
  desc 'check', 'Verify the ASA does not have any unnecessary or non-secure ports, protocols, and services enabled. For example, the following features such as telnet should never be enabled, while other features should only be enabled if required for operations. In the example below, http and telnet service are enabled.

http server enable
…
…
…
telnet 10.1.22.2 255.255.255.255 INSIDE

Note: The command http server enables https and is required for ASDM.

If any unnecessary or non-secure ports, protocols, or services are enabled, this is a finding.'
  desc 'fix', 'Disable features that should not be enabled unless required for operations.

ASA(config)# no http server enable
ASA(config)# no telnet 10.1.22.2 255.255.255.255 INSIDE
ASA(config)# end

Note: Telnet must always be disabled.'
  impact 0.7
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43144r666094_chk'
  tag severity: 'high'
  tag gid: 'V-239911'
  tag rid: 'SV-239911r879588_rule'
  tag stig_id: 'CASA-ND-000430'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-43103r666095_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
