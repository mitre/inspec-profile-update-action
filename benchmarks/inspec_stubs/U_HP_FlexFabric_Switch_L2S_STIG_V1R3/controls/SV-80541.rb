control 'SV-80541' do
  title 'HP FlexFabric Switch must authenticate all network-connected endpoint devices before establishing any connection.'
  desc 'Controlling LAN access via 802.1x authentication or MAC authentication can assist in preventing a malicious user from connecting an unauthorized PC to a switch port to inject or receive data from the network without detection.'
  desc 'check', 'Verify all access switch ports connecting to LAN outlets are configured for 802.1x or MAC authentication as shown in these configuration examples.

802.1x example:

interface Ten-GigabitEthernet1/0/4
port link-mode bridge
port access vlan 200
dot1x

MAC authentication example:

interface Ten-GigabitEthernet1/0/5
port link-mode bridge
port access vlan 200
mac-authentication

If all access switch ports connecting to LAN outlets are not configured for 802.1x or MAC authentication, this is a finding.'
  desc 'fix', 'Configure 802.1 x authentications on all host-facing access switch ports. To authenticate those devices that do not support 802.1x, MAC Authentication Bypass must be configured.

[HP] dot1x
[HP] dot1x authentication-method eap
[HP] domain radius jitc
[HP] radius scheme jitc
[HP-radius-jitc]radius scheme jitc
[HP-radius-jitc]primary authentication 15.252.76.124
[HP-radius-jitc]primary accounting 15.252.76.124
[HP-radius-jitc]accounting-on enable
[HP-radius-jitc]key authentication simple test123
[HP-radius-jitc]user-name-format without-domain
[HP-radius-jitc]nas-ip 15.252.78.99
[HP]domain jitc
[HP-isp-jitc]domain jitc
[HP-isp-jitc]authentication lan-access radius-scheme jitc
[HP-isp-jitc]authorization lan-access radius-scheme jitc
[HP] interface gigbitethernet 1/0/1
[HP-Gigabitethernet1/0/1] undo dot1x handshake
dot1x mandatory-domain jitc
undo dot1x multicast-trigger'
  impact 0.7
  ref 'DPMS Target HP Flex Fabric Switch 7 L2S'
  tag check_id: 'C-66695r1_chk'
  tag severity: 'high'
  tag gid: 'V-66051'
  tag rid: 'SV-80541r1_rule'
  tag stig_id: 'HFFS-L2-000002'
  tag gtitle: 'SRG-NET-000343-L2S-000016'
  tag fix_id: 'F-72127r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
