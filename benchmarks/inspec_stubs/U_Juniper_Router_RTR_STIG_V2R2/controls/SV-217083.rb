control 'SV-217083' do
  title 'The Juniper multicast router must be configured to bind a Protocol Independent Multicast (PIM) neighbor filter to interfaces that have PIM enabled.'
  desc 'PIM is a routing protocol used to build multicast distribution trees for forwarding multicast traffic across the network infrastructure. PIM traffic must be limited to only known PIM neighbors by configuring and binding a PIM neighbor filter to those interfaces that have PIM enabled. If a PIM neighbor filter is not applied to those interfaces that have PIM enabled, unauthorized routers can join the PIM domain, discover and use the rendezvous points, and also advertise their rendezvous points into the domain. This can result in a denial of service by traffic flooding or result in the unauthorized transfer of data.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Verify all interfaces enabled for PIM have a neighbor filter bound to the interface as shown in the example below.

protocols {
    …
    …
    …
    pim {
        interface ge-1/0/1.0 {
            mode sparse;
            neighbor-policy PIM_NBR1_POLICY;
        }
        interface ge-1/1/1.0 {
            mode sparse;
            neighbor-policy PIM_NBR2_POLICY;
        }
        interface ge-2/1/0.0 {
            mode sparse;
            neighbor-policy PIM_NBR3_POLICY;
        }
    }

Review the prefix list and policy statements configured for filtering PIM neighbors as shown in the example below.

policy-options {
    prefix-list PIM_NBR1 {
        x.x.x.x/32;
    }
    prefix-list PIM_NBR2 {
        x.x.x.x/32;
    }
    prefix-list PIM_NBR3 {
        x.x.x.x/32;
    }

    policy-statement PIM_NBR1_POLICY {
        from {
            prefix-list PIM_NBR1;
        }
        then accept;
    }
    policy-statement PIM_NBR2_POLICY {
        from {
            prefix-list PIM_NBR2;
        }
        then accept;
    }
    policy-statement PIM_NBR3_POLICY {
        from {
            prefix-list PIM_NBR3;
        }
        then accept;
    }

If PIM neighbor filters are not bound to all interfaces that have PIM enabled, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure neighbor filters to only accept PIM control plane traffic from documented PIM neighbors. Bind neighbor filters to all PIM enabled interfaces.

Configure prefix list for each neighbor.

[edit policy-options]
set prefix-list PIM_NBR1 x.x.x.x/32
set prefix-list PIM_NBR2 x.x.x.x/32
set prefix-list PIM_NBR3 x.x.x.x/32

Configure policy statements for each PIM neighbor.

[edit policy-options]
set policy-statement PIM_NBR1_POLICY from prefix-list PIM_NBR1
set policy-statement PIM_NBR1_POLICY then accept
set policy-statement PIM_NBR2_POLICY from prefix-list PIM_NBR1
set policy-statement PIM_NBR2_POLICY then accept
set policy-statement PIM_NBR3_POLICY from prefix-list PIM_NBR1
set policy-statement PIM_NBR3_POLICY then accept

Apply the neighbor policy to all interfaces enabled for PIM.

[edit protocols pim]
set interface ge-1/0/1.0 neighbor-policy PIM_NBR1_POLICY 
set interface ge-1/1/1.0 neighbor-policy PIM_NBR1_POLICY 
set interface ge-2/1/0.0 neighbor-policy PIM_NBR1_POLICY'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18312r297117_chk'
  tag severity: 'medium'
  tag gid: 'V-217083'
  tag rid: 'SV-217083r639663_rule'
  tag stig_id: 'JUNI-RT-000790'
  tag gtitle: 'SRG-NET-000019-RTR-000004'
  tag fix_id: 'F-18310r297118_fix'
  tag 'documentable'
  tag legacy: ['V-90949', 'SV-101159']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
