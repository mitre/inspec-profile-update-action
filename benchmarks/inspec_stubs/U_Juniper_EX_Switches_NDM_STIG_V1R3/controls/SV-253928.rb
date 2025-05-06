control 'SV-253928' do
  title 'The Juniper EX switches must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of nonlocal maintenance and diagnostic communications.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network. 

Currently, HMAC is the only FIPS-approved algorithm for generating and verifying message/data authentication codes in accordance with FIPS 198-1. Products that are FIPS 140-2 validated will have an HMAC that meets specification; however, the option must be configured for use as the only message authentication code used for authentication to cryptographic modules.

Separate requirements for configuring applications and protocols used by each application (e.g., SNMPv3, SSHv2, HTTPS, and other protocols and applications that require server/client authentication) are required to implement this requirement. Where SSH is used, the SSHv2 protocol suite is required because it includes Layer 7 protocols such as SCP and SFTP, which can be used for secure file transfers.'
  desc 'check', 'Verify the network device uses FIPS-validated HMAC to protect the integrity of nonlocal maintenance and diagnostic communications.

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

If the network device does not use FIPS-validated HMAC to protect the integrity of nonlocal maintenance and diagnostic communications, this is a finding.'
  desc 'fix', 'Configure the network device to use FIPS-validated HMAC to protect the integrity of nonlocal maintenance and diagnostic communications.

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
set system services ssh key-exchange ecdh-sha2-nistp256'
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57380r904419_chk'
  tag severity: 'high'
  tag gid: 'V-253928'
  tag rid: 'SV-253928r904432_rule'
  tag stig_id: 'JUEX-NM-000510'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-57331r904420_fix'
  tag 'documentable'
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
