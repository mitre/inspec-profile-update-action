control 'SV-256008' do
  title 'The Arista router must be configured to produce audit records containing information to establish where the events occurred.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as router components, modules, device identifiers, node names, and functionality.

Associating information about where the event occurred within the network provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured router.

'
  desc 'check', 'The Arista router must log all packets that have been dropped via the access control list (ACL).

Log output must contain an interface name as to where the packet was filtered.

Step 1: To verify the deny ACL is created with the log statement for dropped packets, execute the command "show ip access-list".

ip access-list test1
 permit ip 10.30.30.0/24 host 10.20.10.1
 deny ip 10.30.10.0/24 host 10.20.10.1 log

Step 2: To verify the ACL ingress is applied on the appropriate interface, execute the command "show run interface YY".

interface ethernet 3
 ip access-group test1 in

######

Variables in the syslog messages display the following values:
---------------------------------------------------------------
acl Name of ACL.
intf Name of interface that received the packet.
filter Action triggered by ACL (denied or permitted).
protocol IP protocol specified by packet.
vlan Number of VLAN receiving packet.
ether EtherType protocol specified by packet.
src-ip and dst-ip source and destination IP addresses.
src-prt and dst-prt source and destination ports.
src-mac and dst-mac source and destination MAC addresses.

If the logged output does not contain an interface name as to where the packet was filtered, this is a finding.

If the Arista router fails to log all packets that have been dropped via the ACL, this is a finding.'
  desc 'fix', 'Configure the router to record the interface in the log record for packets being dropped.

Step 1: Configure the ACL.

router(config)#ip access-list test1
router(config-acl-test1)#15 permit ip 10.30.30.0/24 host 10.20.10.1
router(config-acl-test1)#15 deny ip 10.30.10.0/24 host 10.20.10.1 log

Step 2: Apply the ACL ingress on the appropriate interface.

router(config)#interface ethernet 3
router(config-if-Et3)#ip access-group test1 in'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59684r882364_chk'
  tag severity: 'medium'
  tag gid: 'V-256008'
  tag rid: 'SV-256008r882366_rule'
  tag stig_id: 'ARST-RT-000230'
  tag gtitle: 'SRG-NET-000076-RTR-000001'
  tag fix_id: 'F-59627r882365_fix'
  tag satisfies: ['SRG-NET-000076-RTR-000001', 'SRG-NET-000077-RTR-000001', 'SRG-NET-000078-RTR-000001']
  tag 'documentable'
  tag cci: ['CCI-000132', 'CCI-000133', 'CCI-000134']
  tag nist: ['AU-3 c', 'AU-3 d', 'AU-3 e']
end
