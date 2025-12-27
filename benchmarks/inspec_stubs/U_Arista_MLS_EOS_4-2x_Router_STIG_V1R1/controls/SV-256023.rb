control 'SV-256023' do
  title 'The out-of-band management (OOBM) Arista gateway router must be configured to forward only authorized management traffic to the Network Operations Center (NOC).'
  desc 'The OOBM network is an IP network used exclusively for the transport of OAM&P data from the network being managed to the OSS components located at the NOC. Its design provides connectivity to each managed network device, enabling network management traffic to flow between the managed network elements and the NOC. This allows the use of paths separate from those used by the managed network.'
  desc 'check', 'This requirement is not applicable for the DODIN backbone.

Review the network topology diagram to determine connectivity between the managed network and the NOC.

Review the OOBM gateway router configuration to validate the path that the management traffic traverses.

Step 1: To verify only management traffic is forwarded through the OOBM interface or IPsec tunnel, execute the command "sh ip access-list".

ip access-list OOBM_to_MGMT
   10 permit tcp 10.10.10.0/24 host 10.20.10.1 eq ssh telnet
   20 permit ip 10.10.10.0/24 192.168.10.0/24 
   30 permit udp 10.20.20.0/24 any eq bootps snmp

Step 2: To verify the ACL is applied outbound on the OOBM interface, execute the command "sh run int Eth YY".

interface ethernet 1
  description OOBM to MGMT link
  ip access-group OOBM_to_MGMT out

If traffic other than authorized management traffic is permitted through the OOBM interface or IPsec tunnel, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN backbone.

Configure filters based on port, source IP address, and destination IP address to permit only authorized management traffic into IPsec tunnels or the OOBM interface used for forwarding management data.

Step 1: To configure an ACL to allow only management traffic to be forwarded through the OOBM interface or IPsec tunnel, execute the command "sh ip access-list".

ip access-list OOBM_to_MGMT
   10 permit tcp 10.10.10.0/24 host 10.20.10.1 eq ssh
   20 permit ip 10.10.10.0/24 192.168.10.0/24 
   30 permit udp 10.20.20.0/24 any eq bootps snmp

Step 2: To apply the ACL outbound on the OOBM interface, execute the command "sh run int Eth YY".

interface ethernet 1
  description OOBM to MGMT link
  ip access-group OOBM_to_MGMT out'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59699r882409_chk'
  tag severity: 'medium'
  tag gid: 'V-256023'
  tag rid: 'SV-256023r882411_rule'
  tag stig_id: 'ARST-RT-000420'
  tag gtitle: 'SRG-NET-000205-RTR-000010'
  tag fix_id: 'F-59642r882410_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
