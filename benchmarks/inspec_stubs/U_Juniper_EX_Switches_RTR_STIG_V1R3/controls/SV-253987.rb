control 'SV-253987' do
  title 'The Juniper multicast edge router must be configured to establish boundaries for administratively scoped multicast traffic.'
  desc 'If multicast traffic is forwarded beyond the intended boundary, it is possible that it can be intercepted by unauthorized or unintended personnel.

Administrative scoped multicast addresses are locally assigned and are to be used exclusively by the enterprise network or enclave. Administrative scoped multicast traffic must not cross the enclave perimeter in either direction. Restricting multicast traffic makes it more difficult for a malicious user to access sensitive traffic.

Admin-Local scope is encouraged for any multicast traffic within a network intended for network management, as well as for control plane traffic that must reach beyond link-local destinations.'
  desc 'check', 'Review the router configuration and verify that admin-scope multicast traffic is blocked at the external edge.

Verify either a scope is defined for specific interfaces or a scope policy is applied.
[edit routing-options multicast]
scope <name IPv4> { 
    prefix 239.0.0.0/8;
    interface [ <external interface 1> <external interface 2> ];
}
scope <name IPv6> { 
    prefix ff08::/16;
    interface [ <external interface 1> <external interface 2> ];
}

-or-

[edit policy-options]
policy-statement <name> {
    term 1 {
        from {
            route-filter 239.0.0.0/8 orlonger;
            route-filter ff08::/16 orlonger;
        }
        then reject;
    }
}
[edit routing-options multicast]
scope-policy <policy name>

If the router is not configured to establish boundaries for administratively scoped multicast traffic, this is a finding.'
  desc 'fix', 'Configure the policy to deny packets with multicast administratively scoped destination addresses.
set routing-options multicast scope <IPv4 scope name> prefix 239.0.0.0/8;
set routing-options multicast scope <IPv6 scope name> prefix ff08::/16;

-or-

set policy-options policy-statement <policy name> term 1 from route-filter 239.0.0.0/8 orlonger
set policy-options policy-statement <policy name> term 1 from route-filter ff08::/16 orlonger

Apply the multicast boundary at the appropriate interfaces.
set routing-options multicast scope <IPv4 scope name> interface [ <external interface 1> <external interface 2> ]
set routing-options multicast scope <IPv6 scope name> interface [ <external interface 1> <external interface 2> ]

-or-

set routing-options multicast scope-policy <policy name>'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57439r843992_chk'
  tag severity: 'low'
  tag gid: 'V-253987'
  tag rid: 'SV-253987r843994_rule'
  tag stig_id: 'JUEX-RT-000150'
  tag gtitle: 'SRG-NET-000019-RTR-000005'
  tag fix_id: 'F-57390r843993_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
