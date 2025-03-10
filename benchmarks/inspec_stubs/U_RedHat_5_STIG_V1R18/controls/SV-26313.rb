control 'SV-26313' do
  title 'The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes.'
  desc 'Systems must employ cryptographic hashes for passwords using the SHA-2 family of algorithms or FIPS 140-2 approved successors.  The use of unapproved algorithms may result in weak password hashes more vulnerable to compromise.'
  desc 'check', 'Verify the algorithm used for password hashing is of the SHA-2 family.
# egrep "password .* pam_unix.so" /etc/pam.d/system-auth-ac

# egrep "ENCRYPT_METHOD" /etc/login.defs

# egrep "crypt_style" /etc/libuser.conf

If any output indicates the hash algorithm is not set to sha256 or sha512, this is a finding.'
  desc 'fix', 'Change the default password algorithm.
# authconfig --passalgo=sha512 --update

NOTE: Executing the above command will also update the required parameters in /etc/login.defs and /etc/libuser.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35959r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22303'
  tag rid: 'SV-26313r2_rule'
  tag stig_id: 'GEN000590'
  tag gtitle: 'GEN000590'
  tag fix_id: 'F-31215r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
