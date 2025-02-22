control 'SV-252459' do
  title 'The macOS system must implement approved ciphers to protect the confidentiality of SSH connections.'
  desc 'Unapproved mechanisms for authentication to the cryptographic module are not verified, and therefore cannot be relied upon to provide confidentiality or integrity, resulting in the compromise of DoD data.

Operating systems using encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

The implementation of OpenSSH that is included with macOS does not use a FIPS 140-2 validated cryptographic module. While the listed ciphers are FIPS 140-2 approved algorithms, the module implementing them has not been validated.

By specifying a cipher list with the order of ciphers being in a "strongest to weakest" orientation, the system will automatically attempt to use the strongest cipher for securing SSH connections.

'
  desc 'check', 'If SSH is not being used, this is Not Applicable.

Inspect the "Ciphers" configuration with the following command:
Note: The location of the "sshd_config" file may vary if a different daemon is in use.

# /usr/bin/grep "^Ciphers" /etc/ssh/sshd_config

Ciphers aes256-ctr,aes192-ctr,aes128-ctr

If any ciphers other than "aes256-ctr", "aes192-ctr", or "aes128-ctr" are listed, the order differs from the example above, or the "Ciphers" keyword is missing, this is a finding.'
  desc 'fix', %q(Configure SSH to use secure cryptographic algorithms.

To ensure that "Ciphers" set correctly, run the following command:

/usr/bin/sudo /usr/bin/grep -q '^Ciphers' /etc/ssh/sshd_config && /usr/bin/sudo /usr/bin/sed -i.bak 's/^Ciphers.*/Ciphers aes256-ctr,aes192-ctr,aes128-ctr/' /etc/ssh/sshd_config || /usr/bin/sudo /usr/bin/sed -i.bak '/.*Ciphers and keying.*/a\'$'\nCiphers aes256-ctr,aes192-ctr,aes128-ctr'$'\n' /etc/ssh/sshd_config

The SSH service must be restarted for changes to take effect.)
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55915r816189_chk'
  tag severity: 'medium'
  tag gid: 'V-252459'
  tag rid: 'SV-252459r816455_rule'
  tag stig_id: 'APPL-12-000054'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-55865r816454_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000120-GPOS-00061', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag cci: ['CCI-000803', 'CCI-000068', 'CCI-003123', 'CCI-002890']
  tag nist: ['IA-7', 'AC-17 (2)', 'MA-4 (6)', 'MA-4 (6)']
end
