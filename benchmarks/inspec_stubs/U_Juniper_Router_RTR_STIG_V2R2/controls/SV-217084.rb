control 'SV-217084' do
  title 'The Juniper multicast edge router must be configured to establish boundaries for administratively scoped multicast traffic.'
  desc 'If multicast traffic is forwarded beyond the intended boundary, it is possible that it can be intercepted by unauthorized or unintended personnel.

Administrative scoped multicast addresses are locally assigned and are to be used exclusively by the enterprise network or enclave. Administrative scoped multicast traffic must not cross the enclave perimeter in either direction. Restricting multicast traffic makes it more difficult for a malicious user to access sensitive traffic.

Admin-Local scope is encouraged for any multicast traffic within a network intended for network management, as well as for control plane traffic that must reach beyond link-local destinations.'
  desc 'check', 'Review the router configuration to verify it is blocking admin-scope multicast traffic (239.0.0.0/8) at the multicast domain edge as shown in the example below:

routing-options {
    …
    …
    …
    multicast {
        scope ADMIN_SCOPE {
            prefix 239.0.0.0/8;
            interface [ ge-1/0/1.0 ge-1/1/1.0 ];
        }
    }
}

If the router is not configured to block admin-scoped multicast traffic at the multicast domain edge, this is a finding.'
  desc 'fix', 'Configure the router to block admin-scoped multicast traffic at the multicast domain edge as shown in the example below:

[edit routing-options]
set multicast scope ADMINL_SCOPE interface ge-1/0/1.0 prefix 239.0.0.0/8
set multicast scope ADMINL_SCOPE interface ge-1/1/1.0 prefix 239.0.0.0/8'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18313r297120_chk'
  tag severity: 'low'
  tag gid: 'V-217084'
  tag rid: 'SV-217084r639663_rule'
  tag stig_id: 'JUNI-RT-000800'
  tag gtitle: 'SRG-NET-000019-RTR-000005'
  tag fix_id: 'F-18311r297121_fix'
  tag 'documentable'
  tag legacy: ['SV-101161', 'V-90951']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
