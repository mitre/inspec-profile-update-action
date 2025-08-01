control 'SV-81031' do
  title 'The Juniper SRX Services Gateway must configure the control plane to protect against or limit the effects of common types of Denial of Service (DoS) attacks on the device itself by configuring applicable system options and internet-options.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

Juniper SRX uses the system commands, system internet-options, and screens to mitigate the impact of DoS attacks on device availability.'
  desc 'check', 'Verify the system options are configured to protect against DoS attacks.

[edit]
show system
show system internet-options

If the system and system-options which limit the effects of common types of DoS attacks are not configured in compliance with DoD requirements, this is a finding.'
  desc 'fix', 'Configure the system and system-options to protect against DoS attacks.

[edit]
set system no-redirects
set system no-ping-record-route
set system no-ping-time-stamp
set system internet-options icmpv4-rate-limit packet-rate 50
set system internet-options icmpv6-rate-limit packet-rate 50
set system internet-options no-ipip-path-mtu-discovery
set system internet-options no-source-quench
set system internet-options tcp-drop-synfin-set
set system internet-options no-ipv6-path-mtu-discovery
set system internet-options no-tcp-reset drop-all-tcp'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67187r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66541'
  tag rid: 'SV-81031r1_rule'
  tag stig_id: 'JUSX-DM-000162'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-72617r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
