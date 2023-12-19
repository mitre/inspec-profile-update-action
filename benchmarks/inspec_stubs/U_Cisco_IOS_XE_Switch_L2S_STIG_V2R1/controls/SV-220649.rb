control 'SV-220649' do
  title 'The Cisco switch must uniquely identify all network-connected endpoint devices before establishing any connection.'
  desc 'Controlling LAN access via 802.1x authentication can assist in preventing a malicious user from connecting an unauthorized PC to a switch port to inject or receive data from the network without detection.'
  desc 'check', 'Verify if the switch configuration has 802.1x authentication implemented for all access switch ports connecting to LAN outlets (i.e., RJ-45 wall plates) or devices not located in the telecom room, wiring closets, or equipment rooms. MAC Authentication Bypass (MAB) must be configured on those switch ports connected to devices that do not support an 802.1x supplicant.

Step 1: Verify that 802.1x is configured on all host-facing interfaces as shown in the example below:

interface GigabitEthernet1/0
 switchport access vlan 12
 switchport mode access
 authentication port-control auto
 dot1x pae authenticator
!
interface GigabitEthernet1/1
 switchport access vlan 13
 switchport mode access
 authentication port-control auto
 dot1x pae authenticator
!
interface GigabitEthernet1/2
 switchport access vlan 13
 switchport mode access
 authentication port-control auto
 dot1x pae authenticator

Step 2: Verify that 802.1x authentication is configured on the switch as shown in the example below:

aaa new-model
!
!
aaa group server radius RADIUS_SERVERS
 server name RADIUS_1
 server name RADIUS_2
!
aaa authentication dot1x default group RADIUS_SERVERS
…
…
…
dot1x system-auth-control

Step 3: Verify that the radius servers have been defined.

SW1#show radius server-group RADIUS_SERVERS

Note: Single-host is the default. Host-mode multi-domain (for VoIP phone + PC) or multi-auth (multiple PCs connected to a hub) can be configured as alternatives. Host-mode multi-host is not compliant with this requirement.

If 802.1x authentication or MAB is not configured on all access switch ports connecting to LAN outlets or devices not located in the telecom room, wiring closets, or equipment rooms, this is a finding.'
  desc 'fix', 'Configure 802.1 x authentications on all host-facing access switch ports. To authenticate those devices that do not support 802.1x, MAC Authentication Bypass must be configured.

Step 1: Configure the radius servers as shown in the example below:

SW1(config)#radius server RADIUS_1
SW1(config-radius-server)#address ipv4 10.1.22.3
SW1(config-radius-server)#key xxxxxx
SW1(config-radius-server)#exit
SW1(config)#radius server RADIUS_2
SW1(config-radius-server)#address ipv4 10.1.14.5
SW1(config-radius-server)#key xxxxxx
SW1(config-radius-server)#exit

Step 2: Enable 802.1x authentication on the switch.

SW1(config)#aaa new-model 
SW1(config)#aaa group server radius RADIUS_SERVERS
SW1(config-sg-radius)#server name RADIUS_1
SW1(config-sg-radius)#server name RADIUS_2
SW1(config-sg-radius)#exit
SW1(config)#aaa authentication dot1x default group RADIUS_SERVERS
SW1(config)#dot1x system-auth-control

Step 3: Enable 802.1x on all host-facing interfaces as shown in the example below:

SW1(config)#int range g1/0 - 8
SW1(config-if-range)#switchport mode access 
SW1(config-if-range)#authentication host-mode single-host 
SW1(config-if-range)#dot1x pae authenticator 
SW1(config-if-range)#authentication port-control auto 
SW1(config-if-range)#end 

Note: Single-host is the default. Host-mode multi-domain (for VoIP phone + PC) or multi-auth (multiple PCs connected to a hub) can be configured as alternatives.'
  impact 0.7
  ref 'DPMS Target Cisco IOS XE Switch L2S'
  tag check_id: 'C-22364r507495_chk'
  tag severity: 'high'
  tag gid: 'V-220649'
  tag rid: 'SV-220649r539671_rule'
  tag stig_id: 'CISC-L2-000020'
  tag gtitle: 'SRG-NET-000148-L2S-000015'
  tag fix_id: 'F-22353r507496_fix'
  tag 'documentable'
  tag legacy: ['SV-110269', 'V-101165']
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
