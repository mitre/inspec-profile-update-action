control 'SV-253962' do
  title 'The Juniper EX switch must be configured to enable Storm Control on all host-facing access interfaces.'
  desc 'A traffic storm occurs when packets flood a LAN, creating excessive traffic and degrading network performance. Traffic storm control prevents network disruption by suppressing ingress traffic when the number of packets reaches configured threshold levels. Traffic storm control monitors ingress traffic levels on a port and drops traffic when the number of packets reaches the configured threshold level during any one-second interval.'
  desc 'check', 'Review the switch configuration to verify that storm control is enabled on host-facing access interfaces.
 
Verify storm control profiles at [edit forwarding-options storm-control-profiles] with an appropriate bandwidth value (actual bandwidth value or a percentage). By default, ELS versions of Junos enable storm control with an 80 percent of bandwidth value, but permit setting different values as either an absolute level or a percentage of available bandwidth.

Note: Although percentage of bandwidth remains supported, it is deprecated and subject to removal. Therefore, an absolute level should be used. Threshold values must be configured appropriately for the target network.

Verify the default storm control profile or a custom profile with appropriate bandwidth percentage or level.

[edit forwarding-options]
storm-control-profiles profile-percent {
    all {
        bandwidth-percentage (1..100);
    }
    action-shutdown;
}
storm-control-profiles profile-level {
    all {
        bandwidth-level (100..100000000 kbps);
    }
    action-shutdown;
}
Note: Storm control profiles are created with the hierarchy "all" but support removing specific traffic types using the "no-<traffic type>" keyword. The currently supported exclusions:
  no-broadcast                                 Disable broadcast storm control
  no-multicast                                  Disable multicast storm control
  no-registered-multicast           Disable registered multicast storm control
  no-unknown-unicast                 Disable unknown unicast storm control
  no-unregistered-multicast     Disable unregistered multicast storm control

If excluding traffic, verify at least broadcast storm control is enabled.

Verify that storm control profiles are applied to layer 2 host-facing access interfaces.

[edit interfaces]
<interface name> {
    unit 0 {
        family ethernet-switching {
            storm-control <profile name>;
            recovery-timeout (10..3600 seconds);
        }
    }
}
Note: If a recovery-timeout is not specified, and the storm control profile enforces action-shutdown, affected interfaces are disabled until manually enabled by an authorized administrator.

If storm control is not enabled on all host-facing access interfaces, this is a finding.'
  desc 'fix', 'Configure storm control on each host-facing access interface.

set forwarding-options storm-control-profiles profile-percent all bandwidth-percentage (1..100)
set forwarding-options storm-control-profiles profile-level all bandwidth-level (100..100000000 kbps)

set interfaces <interface name> unit 0 family ethernet-switching storm-control <profile name>
set interfaces <interface name> unit 0 family ethernet-switching recovery-timeout (10..3600 seconds)'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57414r843917_chk'
  tag severity: 'low'
  tag gid: 'V-253962'
  tag rid: 'SV-253962r843919_rule'
  tag stig_id: 'JUEX-L2-000150'
  tag gtitle: 'SRG-NET-000512-L2S-000001'
  tag fix_id: 'F-57365r843918_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
