control 'SV-206653' do
  title 'The layer 2 switch must authenticate all network-connected endpoint devices before establishing any connection.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of authentication claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide authentication decisions (as opposed to the actual authenticators) to the services that need to act on those decisions.

This requirement applies to applications that connect either locally, remotely, or through a network to an endpoint device (including, but not limited to, workstations, printers, servers (outside a datacenter), VoIP Phones, and VTC CODECs). Gateways and SOA applications are examples of where this requirement would apply.

Device authentication is a solution enabling an organization to manage devices. It is an additional layer of authentication ensuring only specific pre-authorized devices can access the system.'
  desc 'check', 'Verify if the switch configuration has 802.1x authentication implemented for all access switch ports connecting to LAN outlets (i.e., RJ-45 wall plates) or devices not located in the telecom room, wiring closets, or equipment rooms. MAC Authentication Bypass (MAB) must be configured on those switch ports connected to devices that do not provide an 802.1x supplicant.

If 802.1x authentication or MAB is not on configured on all access switch ports connecting to LAN outlets or devices not located in the telecom room, wiring closets, or equipment rooms, this is a finding.'
  desc 'fix', 'Configure 802.1 x authentications on all host-facing access switch ports. To authenticate those devices that do not support 802.1x, MAC Authentication Bypass must be configured.'
  impact 0.5
  ref 'DPMS Target Layer 2 Switch'
  tag check_id: 'C-6911r298389_chk'
  tag severity: 'medium'
  tag gid: 'V-206653'
  tag rid: 'SV-206653r383458_rule'
  tag stig_id: 'SRG-NET-000343-L2S-000016'
  tag gtitle: 'SRG-NET-000343'
  tag fix_id: 'F-6911r298390_fix'
  tag 'documentable'
  tag legacy: ['SV-76661', 'V-62171']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
