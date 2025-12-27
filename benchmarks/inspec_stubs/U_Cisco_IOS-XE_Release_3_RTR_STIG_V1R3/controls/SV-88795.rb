control 'SV-88795' do
  title 'The Cisco IOS XE router must be configured so that any key used for authenticating Interior Gateway Protocol peers does not have a duration exceeding 180 days.'
  desc 'If the keys used for routing protocol authentication are guessed, the malicious user could create havoc within the network by advertising incorrect routes and redirecting traffic. Some routing protocols allow the use of key chains for authentication. A key chain is a set of keys that are used in succession, with each having a lifetime of no more than 180 days. Changing the keys frequently reduces the risk of them eventually being guessed.

Keys cannot be used during time periods for which they are not activated. If a time period occurs during which no key is activated, neighbor authentication cannot occur, and therefore routing updates will fail. Therefore, you should ensure that for a given key chain, key activation times overlap to avoid any period of time during which no key is activated.'
  desc 'check', 'Review the Cisco IOS XE router configuration to verify that all IGPs deployed on the router utilizing a key chain do not have a key with a duration exceeding “180” days.

The configuration should look similar to the example below:

interface Ethernet 0
 ip authentication mode eigrp 1 md5
 ip authentication key-chain eigrp 1 KEY_CHAIN
...

router eigrp 1
network x.x.x.x
...

key chain KEY_CHAIN
key 1                                            
 key-string willow            
 accept-lifetime 22:45:00 Feb 10 2016 22:45:00 Aug 10 2016  
 send-lifetime 23:00:00 Feb 10 2016 22:45:00 Aug 10 2016   
key 2                                               
  key-string birch            
  accept-lifetime 22:45:00 Aug 9 2016 22:45:00 Feb 10 2006 
  send-lifetime 23:00:00 Aug 9 2016 22:45:00 Feb 10 2006
key 3                                            
  key-string maple            
  accept-lifetime 22:45:00 Feb 10 2006 22:45:00 Aug 10 2006  
  send-lifetime 23:00:00 Feb 10 2006 22:45:00 Aug 10 2006     

If the Cisco IOS XE router is configured with a key chain with a duration exceeding “180” days, this is a finding.'
  desc 'fix', 'Configure all key chain used for IGP authentication to have keys that will not have a duration exceeding “180” days as shown in the example below:

key chain KEY_CHAIN
key 1                                            
  key-string willow            
  accept-lifetime 22:45:00 Feb 10 2016 22:45:00 Aug 10 2016  
  send-lifetime 23:00:00 Feb 10 2016 22:45:00 Aug 10 2016     
key 2                                               
  key-string birch            
  accept-lifetime 22:45:00 Aug 9 2016 22:45:00 Feb 10 2006 
  send-lifetime 23:00:00 Aug 9 2016 22:45:00 Feb 10 2006
key 3                                            
  key-string maple            
  accept-lifetime 22:45:00 Feb 10 2006 22:45:00 Aug 10 2006  
  send-lifetime 23:00:00 Feb 10 2006 22:45:00 Aug 10 2006'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74207r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74121'
  tag rid: 'SV-88795r2_rule'
  tag stig_id: 'CISR-RT-000013'
  tag gtitle: 'SRG-NET-000025-RTR-000085'
  tag fix_id: 'F-80663r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
