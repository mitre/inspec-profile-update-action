control 'SV-221073' do
  title 'The Cisco switch must be configured to use keys with a duration not exceeding 180 days for authenticating routing protocol messages.'
  desc 'If the keys used for routing protocol authentication are guessed, the malicious user could create havoc within the network by advertising incorrect routes and redirecting traffic. Some routing protocols allow the use of key chains for authentication. A key chain is a set of keys that is used in succession, with each having a lifetime of no more than 180 days. Changing the keys frequently reduces the risk of them eventually being guessed.

Keys cannot be used during time periods for which they are not activated. If a time period occurs during which no key is activated, neighbor authentication cannot occur, and therefore routing updates will fail. Therefore, ensure that for a given key chain, key activation times overlap to avoid any period of time during which no key is activated.'
  desc 'check', 'Review the start times for each key within the configured key chains used for routing protocol authentication as shown in the example below:

key chain OSPF_KEY
 key 1
 key-string 7 070d2e4e4c10
 accept-lifetime 00:00:00 Oct 01 2019 01:05:00 Jan 01 2020
 send-lifetime 00:00:00 Oct 01 2019 23:59:59 Dec 31 2019
 key 2
 key-string 7 0704205e4b07
 accept-lifetime 23:55:00 Dec 31 2019 01:05:00 Apr 01 2020
 send-lifetime 00:00:00 Jan 01 2020 23:59:59 Mar 31 2020

Note: Key chains must be configured to authenticate routing protocol messages as it is the only way to set an expiration.

If any key has a lifetime of more than 180 days, this is a finding.'
  desc 'fix', 'Configure each key used for routing protocol authentication to have a lifetime of no more than 180 days as shown in the example below:

SW1(config)# key chain OSPF_KEY
SW1(config-keychain)# key 1
SW1(config-keychain-key)# key-string xxxxxxxxxxxx
SW1(config-keychain-key)# send-lifetime 00:00:00 Oct 1 2019 23:59:59 Dec 31 2019
SW1(config-keychain-key)# accept-lifetime 00:00:00 Oct 1 2019 01:05:00 Jan 1 2020
SW1(config-keychain-key)# key 2
SW1(config-keychain-key)# key-string kxxxxxxxxxxxxx
SW1(config-keychain-key)# send-lifetime 00:00:00 Jan 1 2020 23:59:59 Mar 31 2020 
SW1(config-keychain-key)# accept-lifetime 23:55:00 Dec 31 2019 01:05:00 Apr 1 2020
SW1(config-keychain-key)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22788r409708_chk'
  tag severity: 'medium'
  tag gid: 'V-221073'
  tag rid: 'SV-221073r856660_rule'
  tag stig_id: 'CISC-RT-000030'
  tag gtitle: 'SRG-NET-000230-RTR-000003'
  tag fix_id: 'F-22777r409709_fix'
  tag 'documentable'
  tag legacy: ['SV-110965', 'V-101861']
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
