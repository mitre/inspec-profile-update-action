control 'SV-253929' do
  title 'The Juniper EX switch must be configured to implement cryptographic mechanisms using a FIPS 140-2 approved algorithm to protect the confidentiality of remote maintenance sessions.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
  desc 'check', 'Review the network device configuration to determine if cryptographic mechanisms are implemented using a FIPS 140-2 approved algorithm to protect the confidentiality of remote maintenance sessions.

If using SNMPv3, verify (minimally) that authentication-sha is configured. Juniper devices also support authentication-sha224/256/384/512. Verify the strongest mutually supported HMAC between the network device and the Network Management Server (NMS) is configured.
[edit system snmp]
v3 {
    usm {
        local-engine {
            user <SNMPv3 user> {
                authentication-sha {
                    authentication-key "PSK"; ## SECRET-DATA
                }
            }
        }
    }
}

Verify SSHv2 is configured for protocol V2 only, ciphers [ aes256-ctr aes192-ctr aes128-ctr aes256-cbc aes192-cbc aes128-cbc ], key-exchange [ ecdh-sha2-nistp521 ecdh-sha2-nistp384 ecdh-sha2-nistp256 ], and macs [ hmac-sha2-512 hmac-sha2-256 hmac-sha1 ].
[edit system services ssh]
:
protocol-version v2;
ciphers [ aes256-ctr aes192-ctr aes128-ctr aes256-cbc aes192-cbc aes128-cbc ];
macs [ hmac-sha2-512 hmac-sha2-256 hmac-sha1 ];
key-exchange [ ecdh-sha2-nistp521 ecdh-sha2-nistp384 ecdh-sha2-nistp256 ];

Juniper network devices support SHA-1 and SHA2-256 NTP authentication keys.
[edit system ntp]
authentication-key 1 type sha256 value "PSK"; ## SECRET-DATA
authentication-key 2 type sha1 value "PSK"; ## SECRET-DATA
server <address 1> key 1 prefer; ## SECRET-DATA
server <address 2> key 2; ## SECRET-DATA
trusted-key [ 1 2 ];

If the network device is not configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions using a FIPS 140-2 approved algorithm, this is a finding.'
  desc 'fix', 'Configure the network device to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions using a FIPS 140-2 approved algorithm.

set snmp v3 usm local-engine user <SNMPv3 user> authentication-sha authentication-password "PSK"
set snmp v3 usm local-engine user <SNMPv3 user> privacy-aes128 privacy-password "PSK"
Note: Use the strongest HMAC mutually supported with the NMS (e.g., authentication-sha256, authentication-sha512)

set system services ssh protocol-version v2
set system services ssh ciphers aes256-ctr
set system services ssh ciphers aes192-ctr
set system services ssh ciphers aes128-ctr
set system services ssh ciphers aes256-cbc
set system services ssh ciphers aes192-cbc
set system services ssh ciphers aes128-cbc
set system services ssh macs hmac-sha2-512
set system services ssh macs hmac-sha2-256
set system services ssh macs hmac-sha1
set system services ssh key-exchange ecdh-sha2-nistp521
set system services ssh key-exchange ecdh-sha2-nistp384
set system services ssh key-exchange ecdh-sha2-nistp256

set system ntp authentication-key 1 type sha256
set system ntp authentication-key 1 value "PSK"
set system ntp authentication-key 2 type sha1
set system ntp authentication-key 2 value "PSK"
set system ntp server <address 1> key 1
set system ntp server <address 1> prefer
set system ntp server <address 2> key 2
set system ntp trusted-key 1
set system ntp trusted-key 2'
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57381r843818_chk'
  tag severity: 'high'
  tag gid: 'V-253929'
  tag rid: 'SV-253929r843820_rule'
  tag stig_id: 'JUEX-NM-000520'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-57332r843819_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
