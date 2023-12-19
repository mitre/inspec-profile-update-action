control 'SV-217900' do
  title 'The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (libuser.conf).'
  desc 'Using a stronger hashing algorithm makes password cracking attacks more difficult.'
  desc 'check', 'Inspect "/etc/libuser.conf" and ensure the following line appears in the "[default]" section: 

crypt_style = sha512


If it does not, this is a finding.'
  desc 'fix', 'In "/etc/libuser.conf", add or correct the following line in its "[defaults]" section to ensure the system will use the SHA-512 algorithm for password hashing: 

crypt_style = sha512'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19381r376715_chk'
  tag severity: 'medium'
  tag gid: 'V-217900'
  tag rid: 'SV-217900r603264_rule'
  tag stig_id: 'RHEL-06-000064'
  tag gtitle: 'SRG-OS-000120'
  tag fix_id: 'F-19379r376716_fix'
  tag 'documentable'
  tag legacy: ['V-38577', 'SV-50378']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
