control 'SV-220679' do
  title 'The Cisco switch must authenticate all endpoint devices before establishing any connection.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of authentication claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide authentication decisions (as opposed to the actual authenticators) to the services that need to act on those decisions.

This requirement applies to applications that connect either locally, remotely, or through a network to an endpoint device (including, but not limited to, workstations, printers, servers (outside a datacenter), VoIP Phones, and VTC CODECs). Gateways and SOA applications are examples of where this requirement would apply.

Device authentication is a solution enabling an organization to manage devices. It is an additional layer of authentication ensuring only specific pre-authorized devices can access the system.'
  desc 'check', 'Verify if the switch configuration has 802.1x authentication implemented for all access switch ports connecting to LAN outlets (i.e., RJ-45 wall plates) or devices not located in the telecom room, wiring closets, or equipment rooms. MAC Authentication Bypass (MAB) must be configured on those switch ports connected to devices that do not provide an 802.1x supplicant.

Step 1: Verify that 802.1x is configured on all host-facing interfaces as shown in the example below:

interface Ethernet1/1
 dot1x pae authenticator
 dot1x port-control auto
 dot1x host-mode single-host
 switchport access vlan 10

interface Ethernet1/2
 dot1x pae authenticator
 dot1x port-control auto
 dot1x host-mode single-host
 switchport access vlan 10

interface Ethernet1/3
 dot1x pae authenticator
 dot1x port-control auto
 dot1x host-mode single-host
 switchport access vlan 10

Note: Host-mode must be set to single-host, multi-domain (for VoIP phone + PC), or multi-auth (multiple PCs connected to a hub). Host-mode multi-host is not compliant with this requirement.

Step 2: Verify that 802.1x authentication is configured on the switch as shown in the example below:

aaa group server radius RADIUS_GROUP 
 server 1.1.1.1 
 server 1.2.1.1 
…
…
…
aaa authentication dot1x default group RADIUS_GROUP

Step 3: Verify that the radius servers have been defined.

radius-server host 10.1.1.1 key 7 "xxxxxxxxxxx" authentication accounting timeout 5 retransmit 1 
radius-server host 10.2.1.1 key 7 " xxxxxxxxxxx" authentication accounting timeout 5 retransmit 1

If 802.1x authentication or MAB is not on configured on all access switch ports connecting to LAN outlets or devices not located in the telecom room, wiring closets, or equipment rooms, this is a finding.'
  desc 'fix', 'Configure 802.1 x authentications on all host-facing access switch ports. To authenticate those devices that do not support 802.1x, MAC Authentication Bypass must be configured.

Step 1: Configure the radius servers as shown in the example below:

SW1(config)# radius-server host 10.1.1.1 key xxxx
SW1(config)# radius-server host 10.2.1.1 key xxxx

Step 2: Enable 802.1x authentication on the switch.

SW1(config)# aaa group server radius RADIUS_GROUP
SW1(config-radius)# server 10.1.1.1
SW1(config-radius)# server 10.2.1.1
SW1(config-radius)# exit
SW1(config)# aaa authentication dot1x default group RADIUS_GROUP
SW1(config)# exit

Step 3: Enable 802.1x on all host-facing interfaces as shown in the example below:

SW1(config)# int e1/1 - 80
SW1(config-if-range)# dot1x port-control auto
SW1(config-if-range)# dot1x host-mode single-host 
SW1(config-if-range)# end

Note: Host-mode must be set to single-host, multi-domain (for VoIP phone + PC), or multi-auth (multiple PCs connected to a hub). Host-mode multi-host is not compliant with this requirement.'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch L2S'
  tag check_id: 'C-22394r539088_chk'
  tag severity: 'medium'
  tag gid: 'V-220679'
  tag rid: 'SV-220679r856488_rule'
  tag stig_id: 'CISC-L2-000080'
  tag gtitle: 'SRG-NET-000343-L2S-000016'
  tag fix_id: 'F-22383r539089_fix'
  tag 'documentable'
  tag legacy: ['SV-110333', 'V-101229']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
