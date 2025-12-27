control 'SV-253992' do
  title 'The Juniper out-of-band management (OOBM) gateway router must be configured to have separate IGP instances for the managed network and management network.'
  desc 'If the gateway router is not a dedicated device for the OOBM network, implementation of several safeguards for containment of management and production traffic boundaries must occur. Since the managed and management network are separate routing domains, configuration of separate Interior Gateway Protocol routing instances is critical on the router to segregate traffic from each network.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Verify that the OOBM interface is an adjacency in the Interior Gateway Protocol routing domain for the management network. Interfaces can only be assigned to one routing instance. 

[edit protocols ospf]
interface <interface name>.<logical unit>; << Cannot be assigned to a virtual routing instance.

[edit routing-instances]
<name> {
    instance-type virtual-router;
    protocols {
        ospf {
            area <area number> {
                interface <interface name>.<logical unit>; << Cannot be assigned to the default routing instance at [edit protocols].
            }
        }
    }
}

Note: If the same interface is assigned to the default routing instance and to a virtual routing instance, commit fails.

Some platforms support a routing-instance using the reserved name "mgmt_junos". On these platforms, configure the "mgmt_junos" instance and apply at the [edit system] hierarchy.
[edit system]
management-instance;

[edit routing-instances]
mgmt_junos {
    routing-options {
        static {
            route 0.0.0.0/0 next-hop <next-hop address>;
        }
    }
}
Note: Not all platforms support routing instances.

If the router does not enforce that Interior Gateway Protocol instances configured on the OOBM gateway router peer only with their own routing domain, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router to enforce that Interior Gateway Protocol instances configured on the OOBM gateway router peer only with their own routing domain.
set protocols ospf area <number> interface <interface name>.<logical unit>

set routing-instances <name> instance-type virtual-router
set routing-instances <name> protocols ospf area <number> interface <interface name>.<logical unit>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57444r844007_chk'
  tag severity: 'medium'
  tag gid: 'V-253992'
  tag rid: 'SV-253992r844009_rule'
  tag stig_id: 'JUEX-RT-000200'
  tag gtitle: 'SRG-NET-000019-RTR-000011'
  tag fix_id: 'F-57395r844008_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
