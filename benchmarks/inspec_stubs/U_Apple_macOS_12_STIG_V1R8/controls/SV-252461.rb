control 'SV-252461' do
  title 'The macOS system must implement approved Key Exchange Algorithms within the SSH server configuration.'
  desc 'Operating systems using encryption are required to use FIPS-compliant mechanisms for authenticating to macOS.

For OpenSSH to utilize the Apple Corecrypto FIPS-validated algorithms, a specific configuration is required to leverage the shim implemented by macOS to bypass the non-FIPS validated LibreSSL crypto module packaged with OpenSSH. Information regarding this configuration can be found in the manual page "apple_ssh_and_fips".

'
  desc 'check', 'Verify the macOS system is configured to use approved SSH Key Exchange Algorithms within the SSH server configuration with the following command:

/usr/bin/sudo /usr/sbin/sshd -T | /usr/bin/grep "kexalgorithms"

kexalgorithms ecdh-sha2-nistp256

If any algorithms other than "ecdh-sha2-nistp256" are listed, or the "kexalgorithms" keyword is missing, this is a finding.'
  desc 'fix', 'Configure the macOS system to use approved SSH Key Exchange Algorithms by creating a plain text file in the /private/etc/ssh/sshd_config.d/ directory containing the following:

KexAlgorithms ecdh-sha2-nistp256

The SSH service must be restarted for changes to take effect.'
  impact 0.7
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55917r922859_chk'
  tag severity: 'high'
  tag gid: 'V-252461'
  tag rid: 'SV-252461r922861_rule'
  tag stig_id: 'APPL-12-000056'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-55867r922860_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000120-GPOS-00061', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00176']
  tag 'documentable'
  tag cci: ['CCI-000803', 'CCI-000068', 'CCI-002890', 'CCI-003123']
  tag nist: ['IA-7', 'AC-17 (2)', 'MA-4 (6)', 'MA-4 (6)']
end
