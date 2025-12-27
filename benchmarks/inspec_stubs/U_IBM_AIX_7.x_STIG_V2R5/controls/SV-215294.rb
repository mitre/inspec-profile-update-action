control 'SV-215294' do
  title 'AIX SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.'
  desc 'DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions.'
  desc 'check', "Check the SSH daemon configuration for allowed MACs by running the following command: 
# grep -i macs /etc/ssh/sshd_config | grep -v '^#' 
MACs hmac-sha1,hmac-sha1-96,hmac-sha2-256,hmac-sha2-256-96,hmac-sha2-512,hmac-sha2-512-96

If no lines are returned, or the returned MAC list contains any MAC that is not FIPS 140-2 approved, this is a finding."
  desc 'fix', 'Edit the "/etc/ssh/sshd_config" file and add/edit the following line to contain FIPS 140-2 approved ciphers:
MACs hmac-sha1,hmac-sha1-96,hmac-sha2-256,hmac-sha2-256-96,hmac-sha2-512,hmac-sha2-512-96

Restart SSH daemon:
# stopsrc -s sshd
# startsrc -s sshd

Note: If the "MACs" configuration contains any ciphers that are not FIPS 140-2 approved, they should be removed from the configuration file.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16492r294333_chk'
  tag severity: 'medium'
  tag gid: 'V-215294'
  tag rid: 'SV-215294r508663_rule'
  tag stig_id: 'AIX7-00-002111'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16490r294334_fix'
  tag 'documentable'
  tag legacy: ['SV-101683', 'V-91585']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
