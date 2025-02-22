control 'SV-220988' do
  title 'The Cisco switch must be configured to use keys with a duration not exceeding 180 days for authenticating routing protocol messages.'
  desc 'If the keys used for routing protocol authentication are guessed, the malicious user could create havoc within the network by advertising incorrect routes and redirecting traffic. Some routing protocols allow the use of key chains for authentication. A key chain is a set of keys that is used in succession, with each having a lifetime of no more than 180 days. Changing the keys frequently reduces the risk of them eventually being guessed.

Keys cannot be used during time periods for which they are not activated. If a time period occurs during which no key is activated, neighbor authentication cannot occur, and therefore routing updates will fail. Therefore, ensure that for a given key chain, key activation times overlap to avoid any period of time during which no key is activated.'
  desc 'check', 'Review the start times for each key within the configured key chains used for routing protocol authentication as shown in the example below:

key chain OSPF_KEY_CHAIN
 key 1
 key-string xxxxxxx
 send-lifetime 00:00:00 Jan 1 2018 23:59:59 Mar 31 2018
 accept-lifetime 00:00:00 Jan 1 2018 01:05:00 Apr 1 2018
 key 2
 key-string yyyyyyy
 send-lifetime 00:00:00 Apr 1 2018 23:59:59 Jun 30 2018
 accept-lifetime 23:55:00 Mar 31 2018 01:05:00 Jul 1 2018

Note: Key chains must be configured to authenticate routing protocol messages, as it is the only way to set an expiration.

If any key has a lifetime of more than 180 days, this is a finding.'
  desc 'fix', 'Configure each key used for routing protocol authentication to have a lifetime of no more than 180 days as shown in the example below:

SW1(config)#key chain OSPF_KEY_CHAIN
SW1(config-keychain)#key 1
SW1(config-keychain-key)#key-string xxxxxx
SW1(config-keychain-key)#send-lifetime 00:00:00 Jan 1 2018 23:59:59 Mar 31 2018
SW1(config-keychain-key)#accept-lifetime 00:00:00 Jan 1 2018 01:05:00 Apr 1 2018
SW1(config-keychain-key)#exit
SW1(config-keychain)#key 2
SW1(config-keychain-key)#key-string yyyyyyy
SW1(config-keychain-key)#send-lifetime 00:00:00 Apr 1 2018 23:59:59 Jun 30 2018
SW1(config-keychain-key)#accept-lifetime 23:55:00 Mar 31 2018 01:05:00 Jul 1 2018
SW1(config-keychain-key)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22703r408758_chk'
  tag severity: 'medium'
  tag gid: 'V-220988'
  tag rid: 'SV-220988r856399_rule'
  tag stig_id: 'CISC-RT-000030'
  tag gtitle: 'SRG-NET-000230-RTR-000003'
  tag fix_id: 'F-22692r408759_fix'
  tag 'documentable'
  tag legacy: ['SV-110797', 'V-101693']
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
