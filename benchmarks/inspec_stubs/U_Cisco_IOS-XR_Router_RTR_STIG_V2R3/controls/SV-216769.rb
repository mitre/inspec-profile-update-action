control 'SV-216769' do
  title 'The Cisco out-of-band management (OOBM) gateway router must be configured to forward only authorized management traffic to the Network Operations Center (NOC).'
  desc 'The OOBM network is an IP network used exclusively for the transport of OAM&P data from the network being managed to the OSS components located at the NOC. Its design provides connectivity to each managed network device, enabling network management traffic to flow between the managed network elements and the NOC. This allows the use of paths separate from those used by the managed network.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the network topology diagram to determine connectivity between the managed network and the NOC. Review the OOBM gateway router configuration to validate the path that the management traffic traverses. Verify that only management traffic is forwarded through the OOBM interface or IPsec tunnel.

If an OOBM link is used, verify that the only authorized management traffic is transported to the NOC by reviewing the outbound ACL applied to the OOBM interface as shown in the example below.

Step 1: Note the outbound ACL applied to the OOBM interface.

interface GigabitEthernet0/0/0/2
 description OOB link to NOC
 ipv4 address 10.11.1.8 255.255.255.0
 ipv4 access-group MGMT_TRAFFIC_ACL egress

Step 2: Review the outbound ACL and verify only management traffic is forwarded to the NOC.

ipv4 access-list MGMT_TRAFFIC_ACL
 10 permit tcp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq tacacs
 20 permit tcp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq ssh
 30 permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq snmp
 40 permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq snmptrap
 50 permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq syslog
 60 permit icmp 10.1.34.0 0.0.0.255 10.22.22.0 0.0.0.255 echo
 70 permit icmp 10.1.34.0 0.0.0.255 10.22.22.0 0.0.0.255 echo-reply
 80 deny ipv4 any any log-input

If an IPSec tunnel is used, verify that the only authorized management traffic is transported to the NOC.

Step 1: Note the profile referenced for the IPSec tunnel to the NOC.

interface tunnel-ipsec 30
 profile IPSEC_NOC_PROFILE
 tunnel source GigabitEthernet0/0/0/2
 tunnel destination x.1.22.2

Step 2: Note the crypto ACL that was specified in the IPSec profile.

 crypto isakmp keyring ISAKMP_KEYRING
 pre-shared-key address x.1.22.2 255.255.255.255 key encrypted 150A13141C32
!
crypto isakmp policy 10
 hash sha256
 encryption aes 256
 authentication pre-share
!
crypto ipsec transform-set IPSEC_TRANS esp-aes 256 esp-sha256-hmac
 mode tunnel
!
crypto ipsec profile IPSEC_NOC_PROFILE
 set pfs group16
 match address MGMT_TRAFFIC_ACL

Step 3: Review the crypto ACL defined in the IPSec profile and verify only management traffic is forwarded to the NOC.

ipv4 access-list MGMT_TRAFFIC_ACL
 10 permit tcp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq tacacs
 20 permit tcp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq ssh
 30 permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq snmp
 40 permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq snmptrap
 50 permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq syslog
 60 permit icmp 10.1.34.0 0.0.0.255 10.22.22.0 0.0.0.255

Note: ICMP is permitted for troubleshooting purposes. The IPSec SA can only identify interesting traffic via address, protocol, and port; hence, the ICMP traffic cannot be qualified via type attribute.

If traffic other than authorized management traffic is permitted through the OOBM interface or IPsec tunnel, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure ACLs to permit only authorized management traffic into IPsec tunnels or the OOBM interface used for forwarding management data as shown in the examples below.

OOBM Link

RP/0/0/CPU0:R3(config)#ipv4 access-list MGMT_TRAFFIC_ACL
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq tacacs
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq ssh
RP/0/0/CPU0:R3(config-ipv4-acl)#permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq snmp
RP/0/0/CPU0:R3(config-ipv4-acl)#permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq snmptrap
RP/0/0/CPU0:R3(config-ipv4-acl)#permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq syslog
RP/0/0/CPU0:R3(config-ipv4-acl)#permit icmp 10.1.34.0 0.0.0.255 10.22.22.0 0.0.0.255
RP/0/0/CPU0:R3(config-ipv4-acl)#deny ipv4 any any log-input
RP/0/0/CPU0:R3(config-ipv4-acl)#exit

IPsec Tunnel

RP/0/0/CPU0:R3(config)#ipv4 access-list MGMT_TRAFFIC_ACL
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq tacacs
RP/0/0/CPU0:R3(config-ipv4-acl)#permit tcp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq ssh
RP/0/0/CPU0:R3(config-ipv4-acl)#permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq snmp
RP/0/0/CPU0:R3(config-ipv4-acl)#permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq snmptrap
RP/0/0/CPU0:R3(config-ipv4-acl)#permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq syslog
RP/0/0/CPU0:R3(config-ipv4-acl)#permit icmp 10.1.34.0 0.0.0.255 10.22.22.0 0.0.0.255
RP/0/0/CPU0:R3(config-ipv4-acl)#exit'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18001r288690_chk'
  tag severity: 'medium'
  tag gid: 'V-216769'
  tag rid: 'SV-216769r531087_rule'
  tag stig_id: 'CISC-RT-000410'
  tag gtitle: 'SRG-NET-000205-RTR-000010'
  tag fix_id: 'F-17999r288691_fix'
  tag 'documentable'
  tag legacy: ['SV-105883', 'V-96745']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
