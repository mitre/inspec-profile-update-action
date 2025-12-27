control 'SV-217013' do
  title 'The Juniper router must be configured to use keys with a duration not exceeding 180 days for authenticating routing protocol messages.'
  desc 'If the keys used for routing protocol authentication are guessed, the malicious user could create havoc within the network by advertising incorrect routes and redirecting traffic. Some routing protocols allow the use of key chains for authentication. A key chain is a set of keys that is used in succession, with each having a lifetime of no more than 180 days. Changing the keys frequently reduces the risk of them eventually being guessed.

Keys cannot be used during time periods for which they are not activated. If a time period occurs during which no key is activated, neighbor authentication cannot occur, and therefore routing updates will fail. Therefore, ensure that for a given key chain, key activation times overlap to avoid any period of time during which no key is activated.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the start times for each key within the configured key chains used for routing protocol authentication as shown in the examples below.

security {
    …
    …
    …
    authentication-key-chains {
        key-chain BGP_KEY {
            key 1 {
                secret "$8$PTQnhclvMX3687"; ## SECRET-DATA
                start-time "2018-5-1.12:00:00 +0000";
            }
            key 2 {
                secret "$8$iq.5OBESyKfTlM"; ## SECRET-DATA
                start-time "2018-9-1.12:00:00 +0000";
            }
            key 3 {
                secret "$8$ZADjqAtOIRSk.hr"; ## SECRET-DATA
                start-time "2019-1-1.12:00:00 +0000";
            }
        }
    }
}

ospf {
        area 0.0.0.0 {
            interface ge-0/0/0.0 {
                authentication {
                    md5 1 key "$8$P5T36/t0ORDi.5F3tp" start-time "2018-1-1.01:01:00 +0000"; ## SECRET-DATA
                    md5 2 key "$8$S.oevLbwg4aUvWxn" start-time "2018-4-1.01:01:00 +0000"; ## SECRET-DATA
                    md5 3 key "$8$SInrWxbO1hcYg4ajH" start-time "2018-8-1.01:01:00 +0000"; ## SECRET-DATA
                }
            }
       }
}

If each key used for routing protocol authentication does not have a lifetime of no more than 180 days, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure each key used for routing protocol authentication to have a lifetime of no more than 180 days as shown in the example below.

[edit security authentication-key-chains]
set key-chain BGP_KEY key 1 start-time 2018-05-01.12:00 secret xxxxxxxxxxxxx
set key-chain BGP_KEY key 2 start-time 2018-09-01.12:00 secret xxxxxxxxxxxxx
set key-chain BGP_KEY key 3 start-time 2019-01-01.12:00 secret xxxxxxxxxxxxx
    }

[edit protocols ospf area 0.0.0.0 interface ge-0/0/0.0]
set authentication md5 1 key xxxxxxxx start-time 2018-01-01.01:01
set authentication md5 2 key xxxxxxxx start-time 2018-04-01.01:01    
set authentication md5 3 key xxxxxxxx start-time 2018-08-01.01:01

Note: Currently Junos does not support key chains for RIP.'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18242r296907_chk'
  tag severity: 'medium'
  tag gid: 'V-217013'
  tag rid: 'SV-217013r604135_rule'
  tag stig_id: 'JUNI-RT-000030'
  tag gtitle: 'SRG-NET-000230-RTR-000003'
  tag fix_id: 'F-18240r296908_fix'
  tag 'documentable'
  tag legacy: ['SV-101021', 'V-90811']
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
