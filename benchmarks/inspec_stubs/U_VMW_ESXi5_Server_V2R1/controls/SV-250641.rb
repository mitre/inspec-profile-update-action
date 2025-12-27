control 'SV-250641' do
  title 'The SSH client must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.'
  desc 'DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions.'
  desc 'check', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# grep -i macs /etc/ssh/ssh_config

Re-enable lock down mode.

If the returned list contains MACs other than a variant of the hmac-sha1 or hmac-sha2 form, this is a finding. If the /etc/ssh/ssh_config file does not exist or the MACs option is not set, this is not a finding.'
  desc 'fix', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# vi /etc/ssh/ssh_config

Add/modify the attribute line entry to the following (quotes for emphasis only):
"MACs <hmac-sha1 or hmac-sha2 variant(s)>"
The above list "may" include any number of the following (current) comma-separated variants: hmac-sha1, hmac-sha1-96, hmac-sha2-256, hmac-sha2-256-96, hmac-sha2-512, hmac-sha2-512-96.

Re-enable lock down mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54076r798920_chk'
  tag severity: 'medium'
  tag gid: 'V-250641'
  tag rid: 'SV-250641r798922_rule'
  tag stig_id: 'SRG-OS-000158-ESXI5'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54030r798921_fix'
  tag 'documentable'
  tag legacy: ['V-39403', 'SV-51261']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
