control 'SV-208839' do
  title 'The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (libuser.conf).'
  desc 'Using a stronger hashing algorithm makes password cracking attacks more difficult.'
  desc 'check', 'Inspect "/etc/libuser.conf" and ensure the following line appears in the "[default]" section: 

crypt_style = sha512

If it does not, this is a finding.'
  desc 'fix', 'In "/etc/libuser.conf", add or correct the following line in its "[defaults]" section to ensure the system will use the SHA-512 algorithm for password hashing: 

crypt_style = sha512'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9092r357497_chk'
  tag severity: 'medium'
  tag gid: 'V-208839'
  tag rid: 'SV-208839r603263_rule'
  tag stig_id: 'OL6-00-000064'
  tag gtitle: 'SRG-OS-000120'
  tag fix_id: 'F-9092r357498_fix'
  tag 'documentable'
  tag legacy: ['SV-65143', 'V-50937']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
