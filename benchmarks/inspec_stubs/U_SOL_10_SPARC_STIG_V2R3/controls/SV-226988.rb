control 'SV-226988' do
  title 'The SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.'
  desc 'DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions.

'
  desc 'check', "Check the SSH daemon configuration for allowed MACs.

Procedure:
# grep -i macs /etc/ssh/sshd_config | grep -v '^#' 

If no lines are returned, or the returned MACs list contains any MAC that is not hmac-sha1 or a better hmac algorithm that is on the FIPS 140-2 approved list, this is a finding."
  desc 'fix', 'Edit the SSH daemon configuration and remove any MACs that are not hmac-sha1 or a better hmac algorithm that is on the FIPS 140-2 approved list. If necessary, add a MACs line.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29150r485303_chk'
  tag severity: 'medium'
  tag gid: 'V-226988'
  tag rid: 'SV-226988r603265_rule'
  tag stig_id: 'GEN005507'
  tag gtitle: 'SRG-OS-000250'
  tag fix_id: 'F-29138r485304_fix'
  tag satisfies: ['SRG-OS-000250', 'SRG-OS-000495', 'SRG-OS-000500']
  tag 'documentable'
  tag legacy: ['SV-26753', 'V-22460']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
