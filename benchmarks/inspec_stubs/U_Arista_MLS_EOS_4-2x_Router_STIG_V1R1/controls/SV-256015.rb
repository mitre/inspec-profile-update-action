control 'SV-256015' do
  title 'The Arista perimeter router must be configured to deny network traffic by default and allow network traffic by exception.'
  desc 'A deny-all, permit-by-exception network communications traffic policy ensures that only connections that are essential and approved are allowed.

This requirement applies to both inbound and outbound network communications traffic. All inbound and outbound traffic must be denied by default. Firewalls and perimeter routers should only allow traffic through that is explicitly permitted. The initial defense for the internal network is to block any traffic at the perimeter that is attempting to make a connection to a host residing on the internal network. In addition, allowing unknown or undesirable outbound traffic by the firewall or router will establish a state that will permit the return of this undesirable traffic inbound.'
  desc 'check', 'This requirement is not applicable for the DODIN backbone.

Review the Arista router configuration to verify the access control list (ACL) or filter is configured to allow specific ports and protocols and deny all other traffic.

The filter must be configured inbound on all external interfaces.

Step 1: Verify the ACL is configured to allow traffic per the requirement and deny all by default. Execute the command "sh ip access-list".

ip access-list INBOUND
   10 permit tcp 10.10.10.0/24 host 10.20.10.1 eq ssh telnet
   20 permit tcp 10.10.10.0/24 any eq www https
   30 permit udp 10.20.20.0/24 any eq bootps snmp

Step 2: Verify the ACL is applied inbound on all external interfaces. Execute the command "sh run int Eth YY".

interface ethernet 13
  ip access-group INBOUND in

If the ACL or filter is not configured to allow specific ports and protocols and deny all other traffic, this is a finding.

If the filter is not configured inbound on all external interfaces, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN backbone.

Configure the Arista perimeter router to deny network traffic by default and allow network traffic by exception.

Step 1: Configure an ACL inbound to allow traffic per the requirement and deny all by default.

ip access-list INBOUND
   10 permit tcp 10.10.10.0/24 host 10.20.10.1 eq ssh telnet
   20 permit tcp 10.10.10.0/24 any eq www https
   30 permit udp 10.20.20.0/24 any eq bootps snmp

Step 2: Apply the ACL inbound on all external interfaces.

router(config)#interface ethernet 13
router(config-if-Et13)#ip access-group INBOUND in'
  impact 0.7
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59691r882385_chk'
  tag severity: 'high'
  tag gid: 'V-256015'
  tag rid: 'SV-256015r882387_rule'
  tag stig_id: 'ARST-RT-000330'
  tag gtitle: 'SRG-NET-000202-RTR-000001'
  tag fix_id: 'F-59634r882386_fix'
  tag 'documentable'
  tag cci: ['CCI-001109']
  tag nist: ['SC-7 (5)']
end
