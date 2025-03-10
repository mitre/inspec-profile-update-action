control 'SV-257166' do
  title 'The macOS system must implement approved Message Authentication Codes (MACs) within the SSH server configuration.'
  desc 'Operating systems using encryption are required to use FIPS-compliant mechanisms for authenticating to macOS.

For OpenSSH to utilize the Apple Corecrypto FIPS-validated algorithms, a specific configuration is required to leverage the shim implemented by macOS to bypass the non-FIPS validated LibreSSL crypto module packaged with OpenSSH. Information regarding this configuration can be found in the manual page "apple_ssh_and_fips".

'
  desc 'check', 'Verify the macOS system is configured to use approved SSH MACs within the SSH server configuration with the following command:

/usr/bin/sudo /usr/sbin/sshd -T | /usr/bin/grep "macs"

macs hmac-sha2-256

If any hashes other than "hmac-sha2-256" are listed, or the "macs" keyword is missing, this is a finding.'
  desc 'fix', 'Configure the macOS system to use approved SSH MACs by creating a plain text file in the /private/etc/ssh/sshd_config.d/ directory containing the following:

MACs hmac-sha2-256

The SSH service must be restarted for changes to take effect.'
  impact 0.7
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60851r919268_chk'
  tag severity: 'high'
  tag gid: 'V-257166'
  tag rid: 'SV-257166r919269_rule'
  tag stig_id: 'APPL-13-000055'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-60792r916573_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000120-GPOS-00061', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00175']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000803', 'CCI-000877', 'CCI-001453', 'CCI-002890', 'CCI-003123']
  tag nist: ['AC-17 (2)', 'IA-7', 'MA-4 c', 'AC-17 (2)', 'MA-4 (6)', 'MA-4 (6)']
end
