control 'SV-220486' do
  title 'The Cisco switch must be configured to prohibit the use of all unnecessary and nonsecure functions and services.'
  desc 'Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved. Some network devices have capabilities enabled by default; if these capabilities are not necessary, they must be disabled. If a particular capability is used, then it must be documented and approved.'
  desc 'check', 'Verify that the switch does not have any unnecessary or non-secure ports, protocols and services enabled. For example, the following features such as telnet should never be enabled, while other features should only be enabled if required for operations.

feature telnet
feature dhcp
feature wccp
feature nxapi
feature imp

If any unnecessary or non-secure ports, protocols, or services are enabled, this is a finding.'
  desc 'fix', 'Disable features that should not be enabled unless required for operations.

SW2(config)# no feature telnet
SW2(config)# no feature dhcp
SW2(config)# no feature wccp
SW2(config)# no feature nxapi
SW2(config)# no feature imp

Note: Telnet must always be disabled.'
  impact 0.7
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22201r539179_chk'
  tag severity: 'high'
  tag gid: 'V-220486'
  tag rid: 'SV-220486r604141_rule'
  tag stig_id: 'CISC-ND-000470'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-22190r539180_fix'
  tag 'documentable'
  tag legacy: ['SV-110621', 'V-101517']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
