control 'SV-215678' do
  title 'The Cisco router must be configured to prohibit the use of all unnecessary and nonsecure functions and services.'
  desc 'Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved. Some network devices have capabilities enabled by default; if these capabilities are not necessary, they must be disabled. If a particular capability is used, then it must be documented and approved.'
  desc 'check', 'Verify that the router does not have any unnecessary or non-secure ports, protocols and services enabled. For example, the following commands should not be in the configuration:

boot network
ip boot server
ip bootp server
ip dns server
ip identd
ip finger
ip http server
ip rcmd rcp-enable
ip rcmd rsh-enable
service config
service finger
service tcp-small-servers
service udp-small-servers

If any unnecessary or non-secure ports, protocols, or services are enabled, this is a finding.'
  desc 'fix', 'Disable the following services if enabled as shown in the example below.

R2(config)#no boot network
R2(config)#no ip boot server
R2(config)#no ip bootp server
R2(config)#no ip dns server
R2(config)#no ip identd
R2(config)#no ip finger
R2(config)#no ip http server
R2(config)#no ip rcmd rcp-enable
R2(config)#no ip rcmd rsh-enable
R2(config)#no service config
R2(config)#no service finger
R2(config)#no service tcp-small-servers
R2(config)#no service udp-small-servers
R2(config)#no service pad
R2(config)#end'
  impact 0.7
  ref 'DPMS Target Cisco IOS Router NDM'
  tag check_id: 'C-16872r285996_chk'
  tag severity: 'high'
  tag gid: 'V-215678'
  tag rid: 'SV-215678r521266_rule'
  tag stig_id: 'CISC-ND-000470'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-16870r285997_fix'
  tag 'documentable'
  tag legacy: ['SV-105195', 'V-96057']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
