control 'SV-233775' do
  title 'The macOS system must implement an approved Key Exchange Algorithm.'
  desc 'Unapproved mechanisms for authentication to the cryptographic module are not verified, and therefore cannot be relied upon to provide confidentiality or integrity, resulting in the compromise of DoD data.

Operating systems using encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

The implementation of OpenSSH that is included with macOS does not utilize a FIPS 140-2 validated cryptographic module. While the listed Key Exchange Algorithms are FIPS 140-2 approved, the module implementing them has not been validated.

By specifying a Key Exchange Algorithm list with the order of hashes being in a “strongest to weakest” orientation, the system will automatically attempt to use the strongest Key Exchange Algorithm for securing SSH connections.

'
  desc 'check', 'If SSH is not being used, this is Not Applicable.

Inspect the "KexAlgorithms" configuration with the following command:
Note: The location of the "sshd_config" file may vary if a different daemon is in use.

/usr/bin/grep  "^KexAlgorithms" /etc/ssh/sshd_config

KexAlgorithms diffie-hellman-group-exchange-sha256

If any algorithm other than "diffie-hellman-group-exchange-sha256" is  listed or the "KexAlgorithms" keyword is missing, this is a finding.'
  desc 'fix', %q(Configure SSH to use a secure Key Exchange Algorithm.

To ensure that "KexAlgorithms" set correctly, run the following command:

/usr/bin/sudo /usr/bin/grep -q '^KexAlgorithms' /etc/ssh/sshd_config && /usr/bin/sudo /usr/bin/sed -i.bak  's/^KexAlgorithms.*/KexAlgorithms diffie-hellman-group-exchange-sha256/' /etc/ssh/sshd_config || /usr/bin/sudo /usr/bin/sed -i.bak '/.*Ciphers and keying.*/a\'$'\n''KexAlgorithms diffie-hellman-group-exchange-sha256'$'\n' /etc/ssh/sshd_config

The SSH service must be restarted for changes to take effect.)
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-33609r591069_chk'
  tag severity: 'medium'
  tag gid: 'V-233775'
  tag rid: 'SV-233775r610285_rule'
  tag stig_id: 'AOSX-14-000056'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-36785r621609_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000120-GPOS-00061', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000803', 'CCI-000877', 'CCI-003123', 'CCI-002890']
  tag nist: ['AC-17 (2)', 'IA-7', 'MA-4 c', 'MA-4 (6)', 'MA-4 (6)']
end
