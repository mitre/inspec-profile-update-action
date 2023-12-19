control 'SV-19076' do
  title 'The network devices management interface must be configured with both an ingress and egress ACL.'
  desc 'The OOBM access switch will connect to the management interface of the managed network device. The management interface can be a true OOBM interface or a standard interface functioning as the management interface. In either case, the management interface of the managed network device will be directly connected to the OOBM network.

An OOBM interface does not forward transit traffic; thereby, providing complete separation of production and management traffic. Since all management traffic is immediately forwarded into the management network, it is not exposed to possible tampering. The separation also ensures that congestion or failures in the managed network do not affect the management of the device. If the device does not have an OOBM port, the interface functioning as the management interface must be configured so that management traffic does not leak into the managed network and that production traffic does not leak into the management network.'
  desc 'check', 'Step 1: Verify the managed interface has an inbound and outbound ACL or filter.

Step 2: Verify the ingress ACL blocks all transit traffic--that is, any traffic not destined to the router itself. In addition, traffic accessing the managed elements should be originated at the NOC.

Step 3: Verify the egress ACL blocks any traffic not originated by the managed element.

If management interface does not have an ingress and egress filter configured and applied, this is a finding.'
  desc 'fix', 'If the management interface is a routed interface, it must be configured with both an ingress and egress ACL. The ingress ACL should block any transit traffic, while the egress ACL should block any traffic that was not originated by the managed network device.'
  impact 0.5
  ref 'DPMS Target Wireless Access Point'
  tag check_id: 'C-19239r5_chk'
  tag severity: 'medium'
  tag gid: 'V-17822'
  tag rid: 'SV-19076r4_rule'
  tag stig_id: 'NET0992'
  tag gtitle: 'The management interface does not have an ACL.'
  tag fix_id: 'F-17737r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
