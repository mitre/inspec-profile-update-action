control 'SV-253911' do
  title 'The Juniper EX switch must be configured to use FIPS 140-2 approved algorithms for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not validated and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Network devices utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. However, authentication algorithms must configure security processes to use only FIPS-approved and NIST-recommended authentication algorithms.'
  desc 'check', 'Determine if the network device uses FIPS 140-2 approved algorithms for authentication to a cryptographic module. 

Verify the password format and SSH use approved algorithms. Verify the random number generator (RNG) is hmac-drbg, a FIPS approved RNG.

[edit system]
login {
    password {
        :
        format <sha-256|sha-512>;
    }
}
services {
    ssh {
        :
        ciphers [ aes256-ctr aes192-ctr aes128-ctr aes256-cbc aes192-cbc aes128-cbc ];
        macs [ hmac-sha2-512 hmac-sha2-256 ];
        key-exchange [ ecdh-sha2-nistp521 ecdh-sha2-nistp384 ecdh-sha2-nistp256 dh-group14-sha1 ];
        :
    }
}
rng {
    hmac-drbg;
}

If the network device is not configured to use a FIPS-approved authentication algorithm to a cryptographic module, this is a finding.'
  desc 'fix', 'Configure the network device to use FIPS 140-2 approved algorithms for authentication to a cryptographic module.

set system login password format <sha-256|sha-512>
set system services ssh ciphers aes256-ctr
set system services ssh ciphers aes192-ctr
set system services ssh ciphers aes128-ctr
set system services ssh ciphers aes256-cbc
set system services ssh ciphers aes192-cbc
set system services ssh ciphers aes128-cbc
set system services ssh macs hmac-sha2-512
set system services ssh macs hmac-sha2-256
set system services ssh key-exchange ecdh-sha2-nistp521
set system services ssh key-exchange ecdh-sha2-nistp384
set system services ssh key-exchange ecdh-sha2-nistp256
set system services ssh key-exchange dh-group14-sha1
set system rng hmac-drbg'
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57363r843764_chk'
  tag severity: 'high'
  tag gid: 'V-253911'
  tag rid: 'SV-253911r879616_rule'
  tag stig_id: 'JUEX-NM-000340'
  tag gtitle: 'SRG-APP-000179-NDM-000265'
  tag fix_id: 'F-57314r843765_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
