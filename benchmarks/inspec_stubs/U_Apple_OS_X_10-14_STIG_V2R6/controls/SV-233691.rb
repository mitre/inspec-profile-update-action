control 'SV-233691' do
  title 'The macOS system must use only Message Authentication Codes (MACs) employing FIPS 140-2 validated cryptographic hash algorithms.'
  desc 'Unapproved mechanisms for authentication to the cryptographic module are not verified, and therefore cannot be relied upon to provide confidentiality or integrity, resulting in the compromise of DoD data.

Operating systems using encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

The implementation of OpenSSH that is included with macOS does not utilize a FIPS 140-2 validated cryptographic module. While the listed MACs are FIPS 140-2 approved algorithms, the module implementing them has not been validated.

By specifying a Keyed-Hash Message Authentication Code list with the order of hashes being in a “strongest to weakest” orientation, the system will automatically attempt to use the strongest hash for securing SSH connections.

'
  desc 'check', 'If SSH is not being used, this is Not Applicable.

Inspect the "MACs" configuration with the following command:
Note: The location of the "sshd_config" file may vary if a different daemon is in use.

/usr/bin/grep  "^Macs" /etc/ssh/sshd_config

MACs hmac-sha2-512,hmac-sha2-256

If any hashes other than "hmac-sha2-512" and/or "hmac-sha2-256" are listed, the order differs from the example above, or  the "MACs" keyword is missing, this is a finding.'
  desc 'fix', %q(Configure SSH to use secure Keyed-Hash Message Authentication Codes.

To ensure that "MACs" set correctly, run the following command:

/usr/bin/sudo /usr/bin/grep -q '^MACs' /etc/ssh/sshd_config && /usr/bin/sudo /usr/bin/sed -i.bak  's/^MACs.*/MACs hmac-sha2-256,hmac-sha2-512/' /etc/ssh/sshd_config || /usr/bin/sudo /usr/bin/sed -i.bak '/.*Ciphers and keying.*/a\'$'\n''MACs hmac-sha2-512,hmac-sha2-256'$'\n' /etc/ssh/sshd_config

The SSH service must be restarted for changes to take effect.)
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-33608r591066_chk'
  tag severity: 'medium'
  tag gid: 'V-233691'
  tag rid: 'SV-233691r610285_rule'
  tag stig_id: 'AOSX-14-000055'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-36784r621606_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000120-GPOS-00061', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag cci: ['CCI-000803', 'CCI-000877', 'CCI-000068', 'CCI-002890', 'CCI-003123']
  tag nist: ['IA-7', 'MA-4 c', 'AC-17 (2)', 'MA-4 (6)', 'MA-4 (6)']
end
