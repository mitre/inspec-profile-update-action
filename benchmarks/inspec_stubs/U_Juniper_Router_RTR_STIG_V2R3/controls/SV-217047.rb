control 'SV-217047' do
  title 'The Juniper out-of-band management (OOBM) gateway router must be configured to not redistribute routes between the management network routing domain and the managed network routing domain.'
  desc 'If the gateway router is not a dedicated device for the OOBM network, several safeguards must be implemented for containment of management and production traffic boundaries; otherwise, it is possible that management traffic will not be separated from production traffic.

Since the managed network and the management network are separate routing domains, separate Interior Gateway Protocol routing instances must be configured on the router, one for the managed network and one for the OOBM network. In addition, the routes from the two domains must not be redistributed to each other.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Verify the Interior Gateway Protocol (IGP) instance used for the managed network does not redistribute routes into the IGP instance used for the management network, and vice versa. The example below imports routes from the global route table (inet.0) in the route table for the management VRF.

}
routing-options {
    interface-routes {
        rib-group inet INET0_GROUP;
    }
    rib-groups {
        INET0_GROUP {
            import-rib [ VRF_MGMT.inet.0 inet.0 ];
        }
    }
}

If the IGP instance used for the managed network redistributes routes into the IGP instance used for the management network, or vice versa, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Remove the configuration that imports routes from the management network into the managed network or vice versa as shown in the example below.

[edit routing-options]
delete rib-groups INET0_GROUP
delete interface-routes rib-group inet INET0_GROUP'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18276r297009_chk'
  tag severity: 'medium'
  tag gid: 'V-217047'
  tag rid: 'SV-217047r604135_rule'
  tag stig_id: 'JUNI-RT-000420'
  tag gtitle: 'SRG-NET-000019-RTR-000012'
  tag fix_id: 'F-18274r297010_fix'
  tag 'documentable'
  tag legacy: ['SV-110193', 'V-90879']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
