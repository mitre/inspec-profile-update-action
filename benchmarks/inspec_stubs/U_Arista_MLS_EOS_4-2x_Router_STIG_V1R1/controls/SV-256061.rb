control 'SV-256061' do
  title 'The PE router must be configured to ignore or block all packets with any IP options.'
  desc 'Packets with IP options are not fast routered and therefore must be punted to the router processor. Hackers who initiate denial-of-service (DoS) attacks on routers commonly send large streams of packets with IP options. Dropping the packets with IP options reduces the load of IP options packets on the router. The end result is a reduction in the effects of the DoS attack on the router and on downstream routers.'
  desc 'check', 'Verify the PE router is configured to block all packets with any IP options with the following command:

router#show run | section IP_Option_ACL
IP Access List IP_Option_ACL
        10 deny ip any any ip-length gt 5
        20 deny any log
!
interface Ethernet25
   description STIG_IP_Option_ACL
   ip access-group IP_Option_ACL in
!

If the perimeter router is not configured to block packets with IP options, this is a finding.'
  desc 'fix', 'Configure the PE router to block packets with IP options with the following commands:

router#config
router(config)# ip access-list IP_Option_ACL
   10 deny ip any any ip-length gt 5 
!
router(config)#interface Ethernet25
 ip access-group IP_Option_ACL in
!'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59737r882523_chk'
  tag severity: 'medium'
  tag gid: 'V-256061'
  tag rid: 'SV-256061r882525_rule'
  tag stig_id: 'ARST-RT-000840'
  tag gtitle: 'SRG-NET-000205-RTR-000016'
  tag fix_id: 'F-59680r882524_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
