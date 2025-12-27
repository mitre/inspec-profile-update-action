control 'SV-217003' do
  title 'The Cisco router must be configured to use keys with a duration not exceeding 180 days for authenticating routing protocol messages.'
  desc 'If the keys used for routing protocol authentication are guessed, the malicious user could create havoc within the network by advertising incorrect routes and redirecting traffic. Some routing protocols allow the use of key chains for authentication. A key chain is a set of keys that is used in succession, with each having a lifetime of no more than 180 days. Changing the keys frequently reduces the risk of them eventually being guessed.

Keys cannot be used during time periods for which they are not activated. If a time period occurs during which no key is activated, neighbor authentication cannot occur, and therefore routing updates will fail. Therefore, ensure that for a given key chain, key activation times overlap to avoid any period of time during which no key is activated.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the start times for each key within the configured key chains used for routing protocol authentication as shown in the example below.

key chain BGP_KEY_CHAIN
 key 1
  accept-lifetime 01:00:00 january 01 2019 01:00:00 april 01 2019
  key-string password 104300150004
  send-lifetime 01:00:00 january 01 2019 01:00:00 april 01 2019
  cryptographic-algorithm HMAC-SHA1-12
 !
 key 2
  accept-lifetime 01:00:00 april 01 2019 01:00:00 july 01 2019
  key-string password 030654090416
  send-lifetime 01:00:00 april 01 2019 01:00:00 july 01 2019
  cryptographic-algorithm HMAC-SHA1-12

Note: Key chains must be configured to authenticate routing protocol messages as it is the only way to set an expiration.

If any key has a lifetime of more than 180 days, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure each key used for routing protocol authentication to have a lifetime of no more than 180 days as shown in the example below.

RP/0/0/CPU0:R2(config)#key chain OSPF_KEY_CHAIN
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN)#key 1
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-1)#accept-lifetime 01:00:00 jan 01 2019 01:00:00 april 01 2019
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-1)#key-string password xxxxxxxxxxxxxxxx
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-1)#send-lifetime 01:00:00 jan 01 2019 01:00:00 april 01 2019
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-1)#cryptographic-algorithm hmac-md5
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-1)#key 2
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-2)#accept-lifetime 01:00:00 april 01 2019 01:00:00 july 01 2019
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-2)#key-string password xxxxxxxxxxxxxxxxxxx
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-2)#send-lifetime 01:00:00 april 01 2019 01:00:00 july 01 2019 
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-2)#cryptographic-algorithm hmac-md5
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-2)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18233r288849_chk'
  tag severity: 'medium'
  tag gid: 'V-217003'
  tag rid: 'SV-217003r531087_rule'
  tag stig_id: 'CISC-RT-000030'
  tag gtitle: 'SRG-NET-000230-RTR-000003'
  tag fix_id: 'F-18231r288850_fix'
  tag 'documentable'
  tag legacy: ['SV-105819', 'V-96681']
  tag cci: ['CCI-002205', 'CCI-000366']
  tag nist: ['AC-4 (17)', 'CM-6 b']
end
