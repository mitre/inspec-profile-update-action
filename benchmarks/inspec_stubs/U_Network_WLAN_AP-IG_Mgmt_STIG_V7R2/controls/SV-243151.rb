control 'SV-243151' do
  title 'The network device must be configured with both an ingress and egress ACL.'
  desc 'Changes to the hardware or software components of the network device can have significant effects on the overall security of the network. Therefore, only qualified and authorized individuals should be allowed administrative access to the network device for implementing any changes or upgrades. This requirement applies to updates of the application files, configuration, ACLs, and policy filters.'
  desc 'check', '1. Verify the managed interface has an inbound and outbound ACL or filter.

2. Verify the ingress ACL blocks all transit traffic (any traffic not destined to the router itself). In addition, traffic accessing the managed elements should be originated at the NOC.

3. Verify the egress ACL blocks any traffic not originated by the managed element.

If the management interface does not have an ingress and egress filter configured and applied, this is a finding.'
  desc 'fix', 'If the management interface is a routed interface, configure it with both an ingress and egress ACL. The ingress ACL should block any transit traffic, while the egress ACL should block any traffic that was not originated by the managed network device.'
  impact 0.5
  ref 'DPMS Target Network WLAN AP-IG Mgmt'
  tag check_id: 'C-46426r719906_chk'
  tag severity: 'medium'
  tag gid: 'V-243151'
  tag rid: 'SV-243151r879887_rule'
  tag stig_id: 'WLAN-ND-001800'
  tag gtitle: 'SRG-APP-000516-NDM-000335'
  tag fix_id: 'F-46383r719907_fix'
  tag 'documentable'
  tag cci: ['CCI-000345', 'CCI-000366']
  tag nist: ['CM-5', 'CM-6 b']
end
