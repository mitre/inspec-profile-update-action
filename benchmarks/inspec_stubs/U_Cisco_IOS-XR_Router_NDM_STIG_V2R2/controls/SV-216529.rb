control 'SV-216529' do
  title 'The Cisco router must be configured to be configured to prohibit the use of all unnecessary and nonsecure functions and services.'
  desc 'Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved. Some network devices have capabilities enabled by default; if these capabilities are not necessary, they must be disabled. If a particular capability is used, then it must be documented and approved.'
  desc 'check', 'Verify that the router does not have any unnecessary or non-secure ports, protocols and services enabled. For example, the following commands should not be in the configuration:

service ipv4 tcp-small-servers max-servers 10
service ipv4 udp-small-servers max-servers 10
http client vrf xxxxx
telnet vrf default ipv4 server max-servers 1

If any unnecessary or non-secure ports, protocols, or services are enabled, this is a finding.'
  desc 'fix', 'Disable the following services if enabled as shown in the example below.

RP/0/0/CPU0:R3(config)#no service ipv4 tcp-small-servers
RP/0/0/CPU0:R3(config)#no service ipv4 udp-small-servers
RP/0/0/CPU0:R3(config)#no http client vrf xxxxx
RP/0/0/CPU0:R3(config)#no telnet ipv4 server'
  impact 0.7
  ref 'DPMS Target Cisco IOS XR Router NDM'
  tag check_id: 'C-17764r288273_chk'
  tag severity: 'high'
  tag gid: 'V-216529'
  tag rid: 'SV-216529r531088_rule'
  tag stig_id: 'CISC-ND-000470'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-17761r288274_fix'
  tag 'documentable'
  tag legacy: ['SV-105541', 'V-96403']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
