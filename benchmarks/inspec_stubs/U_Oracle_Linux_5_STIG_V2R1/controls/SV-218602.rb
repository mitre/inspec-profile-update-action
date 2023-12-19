control 'SV-218602' do
  title 'The SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.'
  desc 'DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions.'
  desc 'check', "Check the SSH daemon configuration for allowed MACs.

Procedure:
# grep -i macs /etc/ssh/sshd_config | grep -v '^#' 

If no lines are returned, or the returned MACs list contains any MAC that is not hmac-sha1 or a better hmac algorithm that is on the FIPS 140-2 approved list, this is a finding."
  desc 'fix', 'Edit the SSH daemon configuration and remove any MACs that are not hmac-sha1 or a better hmac algorithm that is on the FIPS 140-2 approved list. If necessary, add a MACs line.

Restart the SSH daemon.
# /sbin/service sshd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20077r556004_chk'
  tag severity: 'medium'
  tag gid: 'V-218602'
  tag rid: 'SV-218602r603259_rule'
  tag stig_id: 'GEN005507'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-20075r556005_fix'
  tag 'documentable'
  tag legacy: ['V-22460', 'SV-63587']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
