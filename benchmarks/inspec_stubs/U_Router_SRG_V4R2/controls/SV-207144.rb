control 'SV-207144' do
  title 'The router must be configured to only permit management traffic that ingresses and egresses the OOBM interface.'
  desc 'The OOBM access switch will connect to the management interface of the managed network elements. The management interface can be a true OOBM interface or a standard interface functioning as the management interface. In either case, the management interface of the managed network element will be directly connected to the OOBM network.

An OOBM interface does not forward transit traffic, thereby providing complete separation of production and management traffic. Since all management traffic is immediately forwarded into the management network, it is not exposed to possible tampering. The separation also ensures that congestion or failures in the managed network do not affect the management of the device. If the device does not have an OOBM port, the interface functioning as the management interface must be configured so that management traffic does not leak into the managed network and that production traffic does not leak into the management network.'
  desc 'check', 'Step 1: Verify that the managed interface has an inbound and outbound ACL configured.  

Step 2: Verify that the ingress filter only allows management, IGP, and ICMP traffic.

Caveat: If the management interface is a true OOBM interface, this requirement is not applicable.

If the router does not restrict traffic that ingresses and egresses the management interface, this is a finding.'
  desc 'fix', 'If the management interface is a routed interface, it must be configured with both an ingress and egress ACL.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7405r382415_chk'
  tag severity: 'medium'
  tag gid: 'V-207144'
  tag rid: 'SV-207144r604135_rule'
  tag stig_id: 'SRG-NET-000205-RTR-000012'
  tag gtitle: 'SRG-NET-000205'
  tag fix_id: 'F-7405r382416_fix'
  tag 'documentable'
  tag legacy: ['SV-93057', 'V-78351']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
