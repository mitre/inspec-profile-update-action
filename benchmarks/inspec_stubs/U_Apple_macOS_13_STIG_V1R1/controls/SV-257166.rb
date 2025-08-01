control 'SV-257166' do
  title 'The macOS system must implement approved Message Authentication Codes (MACs).'
  desc 'Unapproved mechanisms for authentication to the cryptographic module are not verified and therefore cannot be relied on to provide confidentiality or integrity, resulting in the compromise of DOD data.

Operating systems using encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

The implementation of OpenSSH that is included with macOS does not use a FIPS 140-2 validated cryptographic module. While the listed MACs are FIPS 140-2 approved algorithms, the module implementing them has not been validated.

By specifying a Keyed-Hash Message Authentication Code list with the order of hashes being in a "strongest to weakest" orientation, the system will automatically attempt to use the strongest hash for securing SSH connections.

'
  desc 'check', 'If SSH is not being used, this is not applicable.

Verify the macOS system is configured to use approved SSH MACs with the following command:

/usr/bin/sudo /usr/sbin/sshd -T | /usr/bin/grep "^macs"

macs hmac-sha2-512,hmac-sha2-256

If any hashes other than "hmac-sha2-512" and/or "hmac-sha2-256" are listed, the order differs from the example above, or the "macs" keyword is missing, this is a finding.'
  desc 'fix', "Configure the macOS system to use approved SSH MACs with the following command:

/usr/bin/sudo /usr/bin/grep -q '^MACs' /etc/ssh/sshd_config && /usr/bin/sudo /usr/bin/sed -i.bak 's/^MACs.*/MACs hmac-sha2-256,hmac-sha2-512/' /etc/ssh/sshd_config || /usr/bin/sudo /usr/bin/sed -i.bak '/.*Ciphers and keying.*/a\\'$'\\nMACs hmac-sha2-512,hmac-sha2-256'$'\\n' /etc/ssh/sshd_config

The SSH service must be restarted for changes to take effect."
  impact 0.7
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60851r905129_chk'
  tag severity: 'high'
  tag gid: 'V-257166'
  tag rid: 'SV-257166r905131_rule'
  tag stig_id: 'APPL-13-000055'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-60792r905130_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000120-GPOS-00061', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000803', 'CCI-000877', 'CCI-001453', 'CCI-002890', 'CCI-003123']
  tag nist: ['AC-17 (2)', 'IA-7', 'MA-4 c', 'AC-17 (2)', 'MA-4 (6)', 'MA-4 (6)']
end
