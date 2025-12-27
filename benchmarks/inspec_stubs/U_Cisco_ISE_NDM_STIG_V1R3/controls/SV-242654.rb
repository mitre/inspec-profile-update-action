control 'SV-242654' do
  title 'The Cisco ISE must use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of nonlocal maintenance and diagnostic communications.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 

Currently, HMAC is the only FIPS-approved algorithm for generating and verifying message/data authentication codes in accordance with FIPS 198-1. Products that are FIPS 140-2 validated will have an HMAC that meets specification; however, the option must be configured for use as the only message authentication code used for authentication to cryptographic modules.

Separate requirements for configuring applications and protocols used by each application (e.g., SNMPv3, SSHv2, NTP, HTTPS, and other protocols and applications that require server/client authentication) are required to implement this requirement. Where SSH is used, the SSHv2 protocol suite is required because it includes Layer 7 protocols such as SCP and SFTP, which can be used for secure file transfers.'
  desc 'check', 'Navigate to Administration >> System >> Settings >> FIPS Mode.

Verify FIPS Mode is enabled.

If the Cisco ISE does not generate unique session identifiers using a FIPS 140-2 approved RNG, this is a finding.'
  desc 'fix', 'Enable FIPS Mode in Cisco ISE to ensure DRBG is used for all RNG functions.

1. Choose Administration >> System >> Settings >> FIPS Mode.
2. Choose the "Enabled" option from the FIPS Mode drop-down list.
3. Click "Save" and restart the node.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45929r714270_chk'
  tag severity: 'medium'
  tag gid: 'V-242654'
  tag rid: 'SV-242654r714272_rule'
  tag stig_id: 'CSCO-NM-000490'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-45886r714271_fix'
  tag 'documentable'
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
