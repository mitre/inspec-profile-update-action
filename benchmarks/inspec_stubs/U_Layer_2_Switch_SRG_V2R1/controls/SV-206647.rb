control 'SV-206647' do
  title 'The layer 2 switch must uniquely identify all network-connected endpoint devices before establishing any connection.'
  desc 'Controlling LAN access via 802.1x authentication can assist in preventing a malicious user from connecting an unauthorized PC to a switch port to inject or receive data from the network without detection.'
  desc 'check', 'Verify if the switch configuration has 802.1x authentication implemented for all access switch ports connecting to LAN outlets (i.e., RJ-45 wall plates) or devices not located in the telecom room, wiring closets, or equipment rooms. MAC Authentication Bypass (MAB) must be configured on those switch ports connected to devices that do not support an 802.1x supplicant.

If 802.1x authentication or MAB is not configured on all access switch ports connecting to LAN outlets or devices not located in the telecom room, wiring closets, or equipment rooms, this is a finding.'
  desc 'fix', 'Configure 802.1 x authentications on all host-facing access switch ports. To authenticate those devices that do not support 802.1x, MAC Authentication Bypass must be configured.'
  impact 0.7
  ref 'DPMS Target Layer 2 Switch'
  tag check_id: 'C-6905r298371_chk'
  tag severity: 'high'
  tag gid: 'V-206647'
  tag rid: 'SV-206647r385501_rule'
  tag stig_id: 'SRG-NET-000148-L2S-000015'
  tag gtitle: 'SRG-NET-000148'
  tag fix_id: 'F-6905r298372_fix'
  tag 'documentable'
  tag legacy: ['SV-95193', 'V-62155']
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
