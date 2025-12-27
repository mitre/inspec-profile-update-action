control 'SV-227898' do
  title 'The SSH client must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.'
  desc 'DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions.

'
  desc 'check', "Check the SSH client configuration for allowed MACs.

Procedure:
# grep -i macs /etc/ssh/ssh_config | grep -v '^#' 

If no lines are returned, or the returned MACs list contains any MAC that is not hmac-sha1 or a better hmac algorithm that is on the FIPS 140-2 approved list, this is a finding."
  desc 'fix', 'Edit the SSH client configuration and remove any MACs that are not hmac-sha1 or a better hmac algorithm that is on the FIPS 140-2 approved list. If necessary, add a MACs line.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30060r490099_chk'
  tag severity: 'medium'
  tag gid: 'V-227898'
  tag rid: 'SV-227898r603266_rule'
  tag stig_id: 'GEN005512'
  tag gtitle: 'SRG-OS-000250'
  tag fix_id: 'F-30048r490100_fix'
  tag satisfies: ['SRG-OS-000250', 'SRG-OS-000495', 'SRG-OS-000500']
  tag 'documentable'
  tag legacy: ['V-22463', 'SV-26756']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
