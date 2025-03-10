control 'SV-104541' do
  title 'The Symantec ProxySG must use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of nonlocal maintenance and diagnostic communications.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 

Currently, HMAC is the only FIPS-approved algorithm for generating and verifying message/data authentication codes in accordance with FIPS 198-1. Products that are FIPS 140-2 validated will have an HMAC that meets specification; however, the option must be configured for use as the only message authentication code used for authentication to cryptographic modules.

Separate requirements for configuring applications and protocols used by each application (e.g., SNMPv3, SSHv2, NTP, HTTPS, and other protocols and applications that require server/client authentication) are required to implement this requirement. Where SSH is used, the SSHv2 protocol suite is required because it includes Layer 7 protocols such as SCP and SFTP, which can be used for secure file transfers.'
  desc 'check', 'Verify only FIPS compliant HMAC algorithms are in use.

1. Log on to the CLI via SSH.
2. Type "show management services", press "Enter".
3. Ensure that the "Cipher Suite" attribute lists only cipher suites which use FIPS compliant HMAC algorithms.

If any cipher suites are listed that use non-FIPS compliant HMAC algorithms, this is a finding.'
  desc 'fix', 'Configure the ProxySG to use only FIPS compliant HMAC algorithms.

1. Log on to the CLI via SSH.
2. Type "enable", enter the enable password.
3. Type "configure terminal" and press "Enter".
4. Type "management-services" and press "Enter", type "edit HTTPS-Console" and press "Enter".
5. Type "view" to display the list of configured cipher suites.
6. Type "attribute cipher-suite" followed by a space-delimited list of only cipher suites from step 5 which use FIPS compliant HMAC algorithms and press "Enter".'
  impact 0.7
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93901r1_chk'
  tag severity: 'high'
  tag gid: 'V-94711'
  tag rid: 'SV-104541r1_rule'
  tag stig_id: 'SYMP-NM-000300'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-100829r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
