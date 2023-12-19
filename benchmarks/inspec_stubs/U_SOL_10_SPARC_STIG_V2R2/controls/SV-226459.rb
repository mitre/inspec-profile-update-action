control 'SV-226459' do
  title 'The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes.'
  desc 'Systems must employ cryptographic hashes for passwords using the SHA-2 family of algorithms or FIPS 140-2 approved successors. The use of unapproved algorithms may result in weak password hashes more vulnerable to compromise.'
  desc 'check', 'Verify the traditional UNIX crypt algorithm is deprecated.
# egrep CRYPT_ALGORITHMS_ALLOW /etc/security/policy.conf
If CRYPT_ALGORITHMS_ALLOW is not set, is not set to "6", or is not set to "5,6", this is a finding.

Verify new password hashes are generated using either the SHA-256 or SHA-512 cryptographic hashing algorithm.
# egrep CRYPT_DEFAULT /etc/security/policy.conf
If CRYPT_DEFAULT is not set or is not equal to 5 or 6, this is a finding.'
  desc 'fix', 'Edit the /etc/security/policy.conf file.
# vi /etc/security/policy.conf
Uncomment or add the CRYPT_ALGORITHMS_ALLOW line and set it to "5,6". Update the CRYPT_DEFAULT default line to be equal to 5 or 6. The following lines are acceptable.

CRYPT_ALGORITHMS_ALLOW=5,6
CRYPT_DEFAULT=6'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36380r602743_chk'
  tag severity: 'medium'
  tag gid: 'V-226459'
  tag rid: 'SV-226459r603265_rule'
  tag stig_id: 'GEN000590'
  tag gtitle: 'SRG-OS-000120'
  tag fix_id: 'F-36344r602744_fix'
  tag 'documentable'
  tag legacy: ['V-22303', 'SV-40776']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
