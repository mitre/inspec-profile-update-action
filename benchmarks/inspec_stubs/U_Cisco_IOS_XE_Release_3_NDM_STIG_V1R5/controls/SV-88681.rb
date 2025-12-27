control 'SV-88681' do
  title 'The Cisco IOS XE router must be configured to prohibit the use of all unnecessary or non-secure ports, protocols, or services.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved. Some network devices have capabilities enabled by default; if these capabilities are not necessary, they must be disabled. If a particular capability is used, then it must be documented and approved.'
  desc 'check', 'Verify that the Cisco IOS XE router does not have any unnecessary or non-secure ports, protocols and services enabled. For example, the following commands should not be in the configuration:

ip bootp server
ip dns server
ip finger
ip http server
ip identd
ip rcmd rcp-enable
ip rcmd rsh-enable
service config
service finger
service tcp-small-servers
service udp-small-servers
service pad
transport input telnet
transport output telnet

If any unnecessary or non-secure ports, protocols or services are enabled, this is a finding.'
  desc 'fix', 'Disable all unnecessary or non-secure ports, protocols, and services.

If any of the following commands are in the configuration, remove them.

ip bootp server
ip dns server
ip identd
ip finger
ip http-server
ip rcmd rcp-enable
ip rcmd rsh-enable
service config
service fingerDisable all unnecessary or non-secure ports, protocols and services.

no ip bootp server
no ip dns server
no ip finger
no ip http server
no ip identd
no ip rcmd rcp-enable
no ip rcmd rsh-enable
no service config
no service udp-small-servers
no service tcp-small-servers
no service finger
no service pad
line vty 0 4
no transport input
no transport output
transport input ssh
transport output ssh

Note: transport input and output for telnet service can’t be disabled individually; hence, ssh must be reinserted for access to the line vty configuration.

service tcp-small-servers
service udp-small-servers
service pad'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74091r4_chk'
  tag severity: 'medium'
  tag gid: 'V-74007'
  tag rid: 'SV-88681r3_rule'
  tag stig_id: 'CISR-ND-000047'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-80547r4_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
