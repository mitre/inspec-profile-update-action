control 'SV-202117' do
  title 'The network devices must use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of nonlocal maintenance and diagnostic communications.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 

Currently, HMAC is the only FIPS-approved algorithm for generating and verifying message/data authentication codes in accordance with FIPS 198-1. Products that are FIPS 140-2 validated will have an HMAC that meets specification; however, the option must be configured for use as the only message authentication code used for authentication to cryptographic modules.

Separate requirements for configuring applications and protocols used by each application (e.g., SNMPv3, SSHv2, NTP, HTTPS, and other protocols and applications that require server/client authentication) are required to implement this requirement. Where SSH is used, the SSHv2 protocol suite is required because it includes Layer 7 protocols such as SCP and SFTP, which can be used for secure file transfers.'
  desc 'check', 'Verify the network device uses FIPS-validated HMAC to protect the integrity of nonlocal maintenance and diagnostic communications.

If the network device does not use FIPS-validated HMAC to protect the integrity of nonlocal maintenance and diagnostic communications, this is a finding.'
  desc 'fix', 'Configure the network device to use FIPS-validated HMAC to protect the integrity of nonlocal maintenance and diagnostic communications.'
  impact 0.7
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2243r382031_chk'
  tag severity: 'high'
  tag gid: 'V-202117'
  tag rid: 'SV-202117r400156_rule'
  tag stig_id: 'SRG-APP-000411-NDM-000330'
  tag gtitle: 'SRG-APP-000411'
  tag fix_id: 'F-2244r382032_fix'
  tag 'documentable'
  tag legacy: ['V-55265', 'SV-69511']
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
