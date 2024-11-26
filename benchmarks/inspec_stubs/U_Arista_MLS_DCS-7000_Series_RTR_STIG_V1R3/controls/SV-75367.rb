control 'SV-75367' do
  title 'The Arista Multilayer Switch must enforce that any interface used for out-of-band management traffic is configured to be passive for the Interior Gateway Protocol that is utilized on that management interface.'
  desc 'The out-of-band management access switch will connect to the management interface of the managed network elements. The management interface can be a true out-of-band management interface or a standard interface functioning as the management interface. In either case, the management interface of the managed network element will directly connect to the out-of-band management network.

An out-of-band management interface does not forward transit traffic, thereby providing complete separation of production and management traffic. Since all management traffic is immediately forwarded into the management network, it is not exposed to possible tampering. The separation also ensures that congestion or failures in the managed network do not affect the management of the device. If the device does not have an out-of-band management port, the interface functioning as the management interface must be configured so that management traffic, both data plane and control plane, does not leak into the managed network and that production traffic does not leak into the management network.'
  desc 'check', 'Review the configuration to verify the management interface is configured as passive for the Interior Gateway Protocol instance for the managed network.

The configuration of the routing protocol viewable via the "show running-config" command must include the following statement:

passive-interface [management] [#]

or

passive-interface [default]

Note that not all protocols support the concept of a passive interface, such as the use of BGP for an IGP. As the function of these protocols is different, if this statement is missing from a protocol that does not support this function, this is not a finding.

If the management interface is not configured as passive for the Interior Gateway Protocol instance for the managed network, this is a finding.'
  desc 'fix', 'Configure the management interface as passive for the Interior Gateway Protocol instance configured for the managed network.

From the router configuration interface:

passive-interface management [#]'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61855r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60909'
  tag rid: 'SV-75367r1_rule'
  tag stig_id: 'AMLS-L3-000200'
  tag gtitle: 'SRG-NET-000019-RTR-000014'
  tag fix_id: 'F-66621r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
