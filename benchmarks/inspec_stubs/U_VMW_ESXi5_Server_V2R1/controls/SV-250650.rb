control 'SV-250650' do
  title 'The SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.'
  desc 'DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions.'
  desc 'check', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# grep -i macs /etc/ssh/sshd_config

Re-enable lock down mode.

If the command returns nothing, or the returned list contains MACs other than a variant of the hmac-sha1 or hmac-sha2 format, this is a finding.'
  desc 'fix', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# vi /etc/ssh/sshd_config

Add/modify the attribute line entry to the following (quotes for emphasis only):
"MACs <hmac-sha1 or hmac-sha2 variant(s)>"
The above list "may" include any number of the following (current) comma-separated variants: hmac-sha1, hmac-sha1-96, hmac-sha2-256, hmac-sha2-256-96, hmac-sha2-512, hmac-sha2-512-96.

Re-enable lock down mode.'
  impact 0.7
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54085r798947_chk'
  tag severity: 'high'
  tag gid: 'V-250650'
  tag rid: 'SV-250650r798949_rule'
  tag stig_id: 'SRG-OS-000250-ESXI5'
  tag gtitle: 'SRG-OS-000250-VMM-000860'
  tag fix_id: 'F-54039r798948_fix'
  tag 'documentable'
  tag legacy: ['SV-51273', 'V-39415']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
