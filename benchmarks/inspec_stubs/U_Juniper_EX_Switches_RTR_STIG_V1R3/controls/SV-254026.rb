control 'SV-254026' do
  title 'The Juniper BGP router must be configured to use a unique key for each autonomous system (AS) that it peers with.'
  desc 'If the same keys are used between eBGP neighbors, the chance of a hacker compromising any of the BGP sessions increases. It is possible that a malicious user exists in one autonomous system who would know the key used for the eBGP session. This user would then be able to hijack BGP sessions with other trusted neighbors.'
  desc 'check', 'Interview the ISSM and router administrator to determine if unique keys are being used. 

[edit security ipsec]
security-association <sa name> {
    manual {
        direction bidirectional {
            protocol esp;
            spi <SPI value>;
            authentication {
                algorithm hmac-sha-256-128;
                key ascii-text "$8$aes256-gcm$hmac-sha2-256$100$SpJ/ERRFEsc$y1Wqf1zM3d3xI+ZVB9WzTw$lgM06LJZN3FcVbTaSkDz4g$bZVi57MkUWg"; ## SECRET-DATA
            }
        }
    }
}
[edit protocols bgp]
group <group name> {
    type external;
    local-as <local AS number>;
    neighbor <neighbor 1 address> {
        authentication-key "$8$aes256-gcm$hmac-sha2-256$100$cFQ99Gy83Og$SCMVXvnfna7/cZqH9fCECQ$bCVokm+es94xFJONmbKFNA$4561Uc/r"; ## SECRET-DATA
    }
    neighbor <neighbor 2 address> {
        ipsec-sa <sa name>;
    }
}

Note: Juniper BGP routers support either an MD5 key, rotating MD5 keys, or an IPsec security association (SA). Verify the PSK for each MD5 and SA is different between all neighbors.

If unique keys are not being used, this is a finding.'
  desc 'fix', 'Configure all eBGP routers with unique keys for each eBGP neighbor that it peers with.

set security ipsec security-association <sa name> manual direction bidirectional protocol esp
set security ipsec security-association <sa name> manual direction bidirectional spi <SPI value>
set security ipsec security-association <sa name> manual direction bidirectional authentication algorithm hmac-sha-256-128
set security ipsec security-association <sa name> manual direction bidirectional authentication key ascii-text <PSK value>

set protocols bgp group <group name> type external
set protocols bgp group <group name> local-as <local AS number>
set protocols bgp group <group name> neighbor <neighbor 1 address> authentication-key <PSK value>
set protocols bgp group <group name> neighbor <neighbor 2 address> ipsec-sa test'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57478r844109_chk'
  tag severity: 'medium'
  tag gid: 'V-254026'
  tag rid: 'SV-254026r844111_rule'
  tag stig_id: 'JUEX-RT-000540'
  tag gtitle: 'SRG-NET-000230-RTR-000002'
  tag fix_id: 'F-57429r844110_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
