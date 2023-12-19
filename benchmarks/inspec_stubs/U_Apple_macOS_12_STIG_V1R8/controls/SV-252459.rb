control 'SV-252459' do
  title 'The macOS system must implement approved ciphers within the SSH server configuration to protect the confidentiality of SSH connections.'
  desc 'Operating systems using encryption are required to use FIPS-compliant mechanisms for authenticating to macOS.

For OpenSSH to utilize the Apple Corecrypto FIPS-validated algorithms, a specific configuration is required to leverage the shim implemented by macOS to bypass the non-FIPS-validated LibreSSL crypto module packaged with OpenSSH. Information regarding this configuration can be found in the manual page "apple_ssh_and_fips".

'
  desc 'check', 'Verify the macOS system is configured to use approved SSH ciphers within the SSH server configuration with the following command:

/usr/bin/sudo /usr/sbin/sshd -T | /usr/bin/grep "ciphers"

ciphers aes128-gcm@openssh.com

If any ciphers other than "aes128-gcm@openssh.com" are listed, or the "ciphers" keyword is missing, this is a finding.'
  desc 'fix', 'Configure the macOS system to use approved SSH ciphers by creating a plain text file in the /private/etc/ssh/sshd_config.d/ directory containing the following:

Ciphers aes128-gcm@openssh.com

The SSH service must be restarted for changes to take effect.'
  impact 0.7
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55915r922853_chk'
  tag severity: 'high'
  tag gid: 'V-252459'
  tag rid: 'SV-252459r922855_rule'
  tag stig_id: 'APPL-12-000054'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-55865r922854_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000120-GPOS-00061', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag cci: ['CCI-000803', 'CCI-000068', 'CCI-003123', 'CCI-002890']
  tag nist: ['IA-7', 'AC-17 (2)', 'MA-4 (6)', 'MA-4 (6)']
end
