control 'SV-95609' do
  title 'AAA Services used for 802.1x must be configured to authenticate network endpoint devices (supplicants) before the authenticator establishes any connection.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of authentication claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide authentication decisions (as opposed to the actual authenticators) to the services that need to act on those decisions.

This requirement applies to applications that connect either locally, remotely, or through a network to an endpoint device (including but not limited to workstations, printers, servers [outside a datacenter], VoIP phones, VTC CODECs). Gateways and SOA applications are examples of where this requirement would apply. 

Device authentication is a solution enabling an organization to manage devices. It is an additional layer of authentication ensuring only specific pre-authorized devices can access the system.'
  desc 'check', 'If AAA Services are not used for 802.1x endpoint identification and authentication, this is not applicable.

Verify AAA Services are configured to authenticate supplicants before the authenticator establishes any connection.

If AAA Services are not configured to authenticate supplicants before the authenticator establishes any connection, this is a finding.'
  desc 'fix', 'Configure AAA Services to authenticate supplicants before the authenticator establishes any connection.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80637r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80899'
  tag rid: 'SV-95609r1_rule'
  tag stig_id: 'SRG-APP-000394-AAA-000430'
  tag gtitle: 'SRG-APP-000394-AAA-000430'
  tag fix_id: 'F-87755r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
