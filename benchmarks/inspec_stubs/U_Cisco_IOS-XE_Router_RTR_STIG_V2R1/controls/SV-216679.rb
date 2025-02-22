control 'SV-216679' do
  title 'The Cisco out-of-band management (OOBM) gateway router must be configured to forward only authorized management traffic to the Network Operations Center (NOC).'
  desc 'The OOBM network is an IP network used exclusively for the transport of OAM&P data from the network being managed to the OSS components located at the NOC. Its design provides connectivity to each managed network device, enabling network management traffic to flow between the managed network elements and the NOC. This allows the use of paths separate from those used by the managed network.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the network topology diagram to determine connectivity between the managed network and the NOC. Review the OOBM gateway router configuration to validate the path that the management traffic traverses. Verify that only management traffic is forwarded through the OOBM interface or IPsec tunnel.

If an OOBM link is used, verify that the only authorized management traffic is transported to the NOC by reviewing the outbound ACL applied to the OOBM interface as shown in the example below:

Step 1: Note the outbound ACL applied to the OOBM interface.

interface GigabitEthernet0/2
 description OOB link to NOC
 ip address 10.11.1.8 255.255.255.0
 ip access-group MGMT_TRAFFIC_ACL out

Step 2: Review the outbound ACL and verify only management traffic is forwarded to the NOC.

ip access-list extended MGMT_TRAFFIC_ACL
 permit tcp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq tacacs
 permit tcp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq 22
 permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq snmp
 permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq snmp-trap
 permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq syslog
 permit icmp 10.1.34.0 0.0.0.255 10.22.22.0 0.0.0.255 
 deny   ip any any log-input

If an IPSec tunnel is used, verify that the only authorized management traffic is transported to the NOC.

Step 1: Note the crypto map applied to the external interface.

 interface interface GigabitEthernet0/2
 description link to DISN
 ip address x.1.24.4 255.255.255.0
 crypto map IPSEC_MGMT_MAP

Step 2: Review the crypto map that was bound to the external interface and note the ACL defined that identifies the interesting traffic for the IPsec tunnel.

crypto map IPSEC_MGMT_MAP 10 ipsec-isakmp
 set peer x.1.12.1
 set transform-set TRANS_SET
 match address MGMT_TRAFFIC_ACL

Step 3: Review the ACL defined in the crypto map and verify only management traffic is forwarded to the NOC.

ip access-list extended MGMT_TRAFFIC_ACL
 permit tcp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq tacacs
 permit tcp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq 22
 permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq snmp
 permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq snmp-trap
 permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq syslog
 permit icmp 10.1.34.0 0.0.0.255 10.22.22.0 0.0.0.255

Note: ICMP is permitted for troubleshooting purposes. The IPSec SA can only identify interesting traffic via address, protocol, and port; hence, the ICMP traffic cannot be qualified via type attribute.

If traffic other than authorized management traffic is permitted through the OOBM interface or IPsec tunnel, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure ACLs to permit only authorized management traffic into IPsec tunnels or the OOBM interface used for forwarding management data as shown in the examples below:

OOBM Link:

R4(config)#ip access-list extended MGMT_TRAFFIC_ACL
R4(config-ext-nacl)#permit tcp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq tacacs
R4(config-ext-nacl)#permit tcp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq 22
R4(config-ext-nacl)#permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq snmp
R4(config-ext-nacl)#permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq snmp-trap
R4(config-ext-nacl)#permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq syslog
R4(config-ext-nacl)#permit icmp 10.1.34.0 0.0.0.255 10.22.22.0 0.0.0.255 echo
R4(config-ext-nacl)#permit icmp 10.1.34.0 0.0.0.255 10.22.22.0 0.0.0.255 echo-reply
R4(config-ext-nacl)#deny   ip any any log-input
R4(config-ext-nacl)#exit

IPsec Tunnel:

R4(config)#ip access-list extended MGMT_TRAFFIC_ACL
R4(config-ext-nacl)#permit tcp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq tacacs
R4(config-ext-nacl)#permit tcp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq 22
R4(config-ext-nacl)#permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq snmp
R4(config-ext-nacl)#permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq snmp-trap
R4(config-ext-nacl)#permit udp 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255 eq syslog
R4(config-ext-nacl)#permit icmp 10.1.34.0 0.0.0.255 22.22.22.0 0.0.0.255
R4(config-ext-nacl)#exit'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17912r287988_chk'
  tag severity: 'medium'
  tag gid: 'V-216679'
  tag rid: 'SV-216679r531086_rule'
  tag stig_id: 'CISC-RT-000410'
  tag gtitle: 'SRG-NET-000205-RTR-000010'
  tag fix_id: 'F-17910r287989_fix'
  tag 'documentable'
  tag legacy: ['SV-106069', 'V-96931']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
