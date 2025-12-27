control 'SV-230962' do
  title 'Before establishing a connection with a Network Time Protocol (NTP) server, Forescout must authenticate using a bidirectional, cryptographically based authentication method that uses a FIPS-validated Advanced Encryption Standard (AES) cipher block algorithm to authenticate with the NTP server.'
  desc 'If Network Time Protocol is not authenticated, an attacker can introduce a rogue NTP server. This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate and affect scheduled actions. NTP authentication is used to prevent this tampering by authenticating the time source.

Currently, AES block cipher algorithm is approved for use in DoD for both applying cryptographic protection (e.g., encryption) and removing or verifying the protection that was previously applied (e.g., decryption). NTP devices use MD5 authentication keys. The MD5 algorithm is not specified in either the FIPS or NIST recommendation. However, MD5 is preferred to no authentication at all.

The trusted-key statement permits authenticating NTP servers. The product must be configured to support separate keys for each NTP server. Severs must have a PKI device certificate involved for use in the device authentication process.

Configurable to use SHA-1 when SNMPv3 is configured which is recommended by the vendor and required by DoD. Vendor cautions that this may impact performance with other devices. 

Downgrade to not a finding if correctly configured.'
  desc 'check', 'Review the Forescout configuration to determine if Forescout authenticates SNMP endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.

1. Select Tools >> Options >> Switch.
2. Select a network device and review the "SNMP" tab.
3. Verify the "SNMPv3" option is selected and the "HMAC-SHA" authentication protocol is selected.
4. Verify the "use privacy" radio button is selected and "AES-128" is also selected from the drop-down box.

If SNMPv3 with HMAC-SHA is configured, this is not a finding.'
  desc 'fix', 'Configure Forescout to authenticate SNMP endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.

1. Select Tools >> Options >> Switch.
2. Select a network device and review the "SNMP" tab.
3. Ensure the "SNMPv3" option is selected and the "HMAC-SHA" authentication protocol is selected.
4. Ensure the "use privacy" radio button is selected and "AES-128" is also selected from the drop-down box.

Note: According to the vendor, this configuration uses SHA-1 for NTP configuration only when in FIPS mode. Use of SHA-2 for integrity processes usually incurs a finding, however this configuration sets AES-128. Thus, this vendor-recommended configuration is considered to mitigate the risk for NTP on Forescout only. This is specifically and only applicable to this requirement.'
  impact 0.5
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33892r603725_chk'
  tag severity: 'medium'
  tag gid: 'V-230962'
  tag rid: 'SV-230962r615886_rule'
  tag stig_id: 'FORE-NM-000361'
  tag gtitle: 'SRG-APP-000395-NDM-000347'
  tag fix_id: 'F-33865r603726_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
