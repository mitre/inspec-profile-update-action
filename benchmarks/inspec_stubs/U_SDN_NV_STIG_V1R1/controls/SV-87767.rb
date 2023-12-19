control 'SV-87767' do
  title 'A secondary IP address must be specified for the virtual tunnel endpoint (VTEP) loopback interface when Virtual Extensible Local Area Network (VXLAN) enabled switches are deployed as a multi-chassis configuration.'
  desc 'A multi-chassis configuration (i.e., vPC domain, MLAG, MCLAG, etc.) can be used to attach a hypervisor host to a pair of VXLAN-enabled switches. For example, a vPC consists of two vPC peer switches connected by a vPC peer link. A vPC domain is formed by the two switches; one switch is primary and the other is secondary. A switch can only be part of one vPC domain, and only two switches can make up a vPC domain.

A vPC allows links that are physically connected to two different switches to appear as a single port channel to a third device, which can be another switch or a server that supports Link Aggregation Control Protocol (LACP) as defined in IEEE 802.1AX, 802.1aq, and 802.3ad. With vPC deployment, the loopback interface that is acting as the source-interface for the VTEP will use the secondary IP address to function as the anycast IP address if the hypervisor host is dual-attached through the vPC. When a host is single-attached (orphan port), the VXLAN-encapsulated traffic will be sent using the loopback’s primary address.'
  desc 'check', 'Review the VXLAN topology to determine if any hypervisor hosts are dual-homed to two VXLAN-enabled switches deployed as multi-chassis configuration (e.g., vPC domain, MLAG, MCLAG, etc.) to function as a single VTEP. 

For VXLAN-enabled switches deployed as a multi-chassis configuration, review the configuration to verify that a secondary IP address has been defined for the VTEP loopback interface. 

If a secondary IP address has not been configured for the VTEP, this is a finding.'
  desc 'fix', 'Configure a secondary IP address for all VTEP loopback interfaces for VXLAN-enabled switches deployed as a multi-chassis configuration to function as a single VTEP for dual-homed attached hypervisor hosts.'
  impact 0.3
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73249r1_chk'
  tag severity: 'low'
  tag gid: 'V-73115'
  tag rid: 'SV-87767r1_rule'
  tag stig_id: 'NET-SDN-025'
  tag gtitle: 'NET-SDN-025'
  tag fix_id: 'F-79561r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
