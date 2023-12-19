control 'SV-207143' do
  title 'The out-of-band management (OOBM) gateway router must be configured to block any traffic destined to itself that is not sourced from the OOBM network or the NOC.'
  desc 'If the gateway router is not a dedicated device for the OOBM network, several safeguards must be implemented for containment of management and production traffic boundaries. It is imperative that hosts from the managed network are not able to access the OOBM gateway router.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the access control list (ACL) or filter for the router receive path.

Verify that only traffic sourced from the OOBM network or the NOC is allowed to access the router.

If the router does not block any traffic destined to itself that is not sourced from the OOBM network or the NOC, this is a finding.

Note: If the platform does not support the receive path filter, verify that all non-OOBM interfaces have an ingress ACL to restrict access to that interface address or any of the router’s loopback addresses to only traffic sourced from the management network. An exception would be to allow packets destined to these interfaces used for troubleshooting, such as ping and traceroute.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Ensure that traffic from the managed network is not able to access the OOBM gateway router using either receive path or interface ingress ACLs.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7404r382412_chk'
  tag severity: 'medium'
  tag gid: 'V-207143'
  tag rid: 'SV-207143r604135_rule'
  tag stig_id: 'SRG-NET-000205-RTR-000011'
  tag gtitle: 'SRG-NET-000205'
  tag fix_id: 'F-7404r382413_fix'
  tag 'documentable'
  tag legacy: ['SV-93063', 'V-78357']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
