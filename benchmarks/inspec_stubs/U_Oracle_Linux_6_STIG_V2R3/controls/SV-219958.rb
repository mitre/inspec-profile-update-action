control 'SV-219958' do
  title 'The Oracle Linux operating system must be configured so that the SSH daemon is configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.'
  desc 'DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions. The only SSHv2 hash algorithm meeting this requirement is SHA.
By specifying a hash algorithm list with the order of hashes being in a “strongest to weakest” orientation, the system will automatically attempt to use the strongest hash for securing SSH connections.'
  desc 'check', 'Verify the SSH daemon is configured to only use MACs employing FIPS 140-2-approved hashes.

Note: If OL6-00-000534 is a finding, this is automatically a finding as the system cannot implement FIPS 140-2-approved cryptographic algorithms and hashes.

Check that the SSH daemon is configured to only use MACs employing FIPS 140-2-approved hashes with the following command:

# grep -i macs /etc/ssh/sshd_config
MACs hmac-sha2-512,hmac-sha2-256

If any hashes other than "hmac-sha2-512" or "hmac-sha2-256" are listed, the order differs from the example above, they are missing, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for the "MACs" keyword and set its value to "hmac-sha2-512, hmac-sha2-256" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):

MACs hmac-sha2-512,hmac-sha2-256

The SSH service must be restarted for changes to take effect.
# sudo service sshd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21668r622248_chk'
  tag severity: 'medium'
  tag gid: 'V-219958'
  tag rid: 'SV-219958r603346_rule'
  tag stig_id: 'OL6-00-000228'
  tag gtitle: 'SRG-OS-000250'
  tag fix_id: 'F-21667r622249_fix'
  tag 'documentable'
  tag legacy: ['SV-109113', 'V-100009']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
