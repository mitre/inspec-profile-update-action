control 'SV-256009' do
  title 'The Arista router must be configured to have all non-essential capabilities disabled.'
  desc 'A compromised router introduces risk to the entire network infrastructure, as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy, including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each router is to enable only the capabilities required for operation.'
  desc 'check', 'Review the Arista router configuration to determine if services or functions not required for operation or not related to router functionality (e.g., DNS, email client or server, FTP server, or web server) are enabled.

The Arista router commands can disable any individual features not required.

router(config)#no ip ftp [source] interfaceno logging console
no ip domain lookup source-interface lo0 
no ntp
no mlag configuration 
no dhcp server
no dns domain
snmp-server community community1 ro
vlan 1 trunk group DO_NOT_USE
logging trap 6

The Arista router configuration sample below demonstrates the default security configuration and available services that can be configured.

!
management console
   idle-timeout 0
!
management ssh
   idle-timeout 0
!
management telnet
   shutdown
   idle-timeout 0
!
aaa authentication login default local
no aaa authentication login console
aaa authentication enable default local
no aaa authorization console
no aaa authorization exec default
no aaa authorization commands all default
aaa authorization config-commands
no aaa accounting exec console
no aaa accounting commands all console
no aaa accounting exec default
no aaa accounting commands all default
!
no enable secret
no aaa root
no aaa authentication policy local allow-nopassword-remote-login
!
username admin privilege 1 nopassword
!
no radius-server key
radius-server timeout 5
radius-server retransmit 3
no radius-server deadtime
!
no snmp-server engineID local
no snmp-server chassis-id
no snmp-server contact
no snmp-server location
no snmp-server source-interface
snmp-server enable traps
default snmp-server enable traps entity
default snmp-server enable traps lldp
default snmp-server enable traps snmp
default snmp-server enable traps spanning-tree
default snmp-server enable traps test
!
spanning-tree mode mstp
spanning-tree max-age 20
spanning-tree forward-time 15
spanning-tree transmit hold-count 6
spanning-tree max-hops 20
no spanning-tree portfast bpduguard default
no spanning-tree loopguard default
spanning-tree bpduguard rate-limit default
spanning-tree mst 0 priority 32768
!
control-plane
   ip access-group default-control-plane-acl in
!
no tacacs-server key
tacacs-server timeout 5
!
no banner login
no banner motd
!
 
Note that only SSH is enabled by default. All cleartext protocols (telnet, SNMP) are disabled by default.

If unnecessary services and functions are enabled on the Arista router, this is a finding.'
  desc 'fix', 'Remove unneeded services and functions from the router. Removal is recommended because the service or function may be inadvertently enabled otherwise. However, if removal is not possible, disable the service or function.

Step 1: Configure the Arista device to disable the features that are not required.

no logging console
no ip domain lookup source-interface lo0 
no ntp
no mlag configuration 
no dhcp server 

Step 2: Configure the Arista device to disable the use of VLAN 1.

vlan 1 state suspend 
interface e1
!

Step 3: Configure all unused ports to designated VLAN and suspend the VLAN to disable all unused ports.

   routerport trunk native vlan 1000 
   routerport trunk allowed vlan except 1'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59685r882367_chk'
  tag severity: 'low'
  tag gid: 'V-256009'
  tag rid: 'SV-256009r882369_rule'
  tag stig_id: 'ARST-RT-000260'
  tag gtitle: 'SRG-NET-000131-RTR-000035'
  tag fix_id: 'F-59628r882368_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
