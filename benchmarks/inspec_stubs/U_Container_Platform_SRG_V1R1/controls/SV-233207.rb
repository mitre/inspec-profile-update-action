control 'SV-233207' do
  title 'Container platform applications and Application Program Interfaces (API) used for nonlocal maintenance sessions must use FIPS-validated keyed-hash message authentication code (HMAC) to protect the integrity of nonlocal maintenance and diagnostic communications.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified, and therefore cannot be relied on to provide confidentiality or integrity, and DoD data may be compromised.

Nonlocal maintenance and diagnostic activities are activities conducted by individuals communicating through either an external network (e.g., the internet) or an internal network.

Currently, HMAC is the only FIPS-approved algorithm for generating and verifying message/data authentication codes in accordance with FIPS 198-1. Products that are FIPS 140-2 validated will have an HMAC that meets specification; however, the option must be configured for use as the only message authentication code used for authentication to cryptographic modules.

Separate requirements for configuring applications and protocols used by each product (e.g., SNMPv3, SSHv2, NTP, and other protocols and applications that require server/client authentication) are required to implement this requirement. The SSHv2 protocol suite must be mandated in the product because it includes layer 7 protocols such as SCP and SFTP that can be used for secure file transfers.'
  desc 'check', 'Validate that container platform applications and APIs used for nonlocal maintenance sessions are using FIPS-validated HMAC to protect the integrity of nonlocal maintenance and diagnostic communications. 

If the sessions are not using FIPS-validated HMAC, this is a finding.'
  desc 'fix', 'Configure the container platform applications and APIs used for nonlocal maintenance sessions to use FIPS-validated HMAC to protect the integrity of nonlocal maintenance and diagnostic communications.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36143r599652_chk'
  tag severity: 'medium'
  tag gid: 'V-233207'
  tag rid: 'SV-233207r599717_rule'
  tag stig_id: 'SRG-APP-000411-CTR-000995'
  tag gtitle: 'SRG-APP-000411'
  tag fix_id: 'F-36111r599258_fix'
  tag 'documentable'
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
