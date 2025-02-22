control 'SV-255968' do
  title 'The Arista MLS layer 2 switch must uniquely identify all network-connected endpoint devices before establishing any connection.'
  desc 'Controlling LAN access via 802.1x authentication can assist in preventing a malicious user from connecting an unauthorized PC to a switch port to inject or receive data from the network without detection.

'
  desc 'check', 'Verify the Arista MLS switch configuration has 802.1x authentication implemented for all access switch ports connecting to LAN outlets (i.e., RJ-45 wall plates) or devices not located in the telecom room, wiring closets, or equipment rooms. MAC Authentication Bypass (MAB) must be configured on  switch ports connected to devices that do not provide an 802.1x supplicant.

Verify the Arista MLS switch configuration for 802.1x is configured globally and, on the required host-based access ports or MAB, is configured on ports that require RADIUS and MAC-based supplicants.

switch# show run | section dot1x
logging level DOT1X informational 
aaa authentication dot1x default group radius 
dot1x system-auth-control
!
interface Ethernet6
   description 802.1X Access Network
   switchport access vlan 100
   dot1x pae authenticator
   dot1x reauthentication
   dot1x port-control auto
   dot1x host-mode single-host
   dot1x timeout quiet-period 10
!
interface Ethernet7
   description STIG MAC-Based Authentication
   speed 100full
   dot1x pae authenticator
   dot1x port-control auto
   dot1x mac based authentication
!

If 802.1x authentication or MAB is not configured on all access switch ports connecting to LAN outlets or devices not located in the telecom room, wiring closets, or equipment rooms, this is a finding.'
  desc 'fix', 'Configure Arista MLS switch for 802.1X globally with the following mandatory parameters, and then configure non-data center access ports and all applicable interfaces.

Step 1: Configure the Arista MLS switch for 802.1X globally using the following commands:

! 
logging level DOT1X informational 
aaa authentication dot1x default group radius 
dot1x system-auth-control
!

Step 2: Configure the Arista switch for all non-data center access ports with 802.1X VLAN to an access/trunk port and set the 802.1X port access entity (PAE) to authenticator with the following commands:

interface Ethernet4
description 802.1X Host-Mode Access Port
   switchport access vlan 100
   dot1x pae authenticator
   dot1x reauthentication
   dot1x port-control auto
   dot1x host-mode single-host
   dot1x timeout quiet-period 10
!

Step 3: The Arista switch can be also configured for MAC-based authentication. Configuring MAB requires that every supplicant trying to gain access to the switch authenticator port is individually authenticated by MAC address as opposed to authenticating just one supplicant on a given VLAN or port with 802.1X, and then using the MAC address of these devices as username and password in the RADIUS request packets.

!
interface Ethernet7
 description MAC-Based Authentication
   speed 100full
   dot1x pae authenticator
   dot1x port-control auto
   dot1x mac based authentication
!'
  impact 0.7
  ref 'DPMS Target Arista MLS EOS 4.2x L2S'
  tag check_id: 'C-59644r882244_chk'
  tag severity: 'high'
  tag gid: 'V-255968'
  tag rid: 'SV-255968r882246_rule'
  tag stig_id: 'ARST-L2-000020'
  tag gtitle: 'SRG-NET-000148-L2S-000015'
  tag fix_id: 'F-59587r882245_fix'
  tag satisfies: ['SRG-NET-000148-L2S-000015', 'SRG-NET-000343-L2S-000016']
  tag 'documentable'
  tag cci: ['CCI-000778', 'CCI-001958']
  tag nist: ['IA-3', 'IA-3']
end
