control 'SV-95607' do
  title 'AAA Services used for 802.1x must be configured to uniquely identify network endpoints (supplicants) before the authenticator establishes any connection.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of identification claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide the identification decisions (as opposed to the actual identifiers) to the services that need to act on those decisions.

This requirement applies to applications that connect either locally, remotely, or through a network to an endpoint device (including but not limited to workstations, printers, servers [outside a datacenter], VoIP phones, VTC CODECs). Gateways and SOA applications are examples of where this requirement would apply.'
  desc 'check', 'If AAA Services are not used for 802.1x endpoint identification and authentication, this is not applicable.

Verify AAA Services are configured to uniquely identify supplicants before the authenticator establishes any connection.

If AAA Services are not configured to uniquely identify supplicants before the authenticator establishes any connection, this is a finding.'
  desc 'fix', 'Configure AAA Services for 802.1x identification and authentication to uniquely identify supplicants before the authenticator establishes any connection.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80635r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80897'
  tag rid: 'SV-95607r1_rule'
  tag stig_id: 'SRG-APP-000158-AAA-000420'
  tag gtitle: 'SRG-APP-000158-AAA-000420'
  tag fix_id: 'F-87753r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
