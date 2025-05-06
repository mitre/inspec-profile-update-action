control 'SV-226460' do
  title 'The password hashes stored on the system must have been generated using a FIPS 140-2 approved cryptographic hashing algorithm.'
  desc 'Systems must employ cryptographic hashes for passwords using the SHA-2 family of algorithms or FIPS 140-2 approved successors. The use of unapproved algorithms may result in weak password hashes more vulnerable to compromise.'
  desc 'check', "Determine if any password hashes stored on the system were not generated using a FIPS 140-2 approved cryptographic hashing algorithm.

Procedure:
# cut -d ':' -f2 /etc/passwd
# cut -d ':' -f2 /etc/shadow

If any password hashes are present not beginning with $5$ or $6$,  this is a finding.

Verify that FIPS 140-2 approved cryptographic hashing algorithms are available.
# egrep '^[56]' /etc/security/crypt.conf
If no lines are returned, this is a finding."
  desc 'fix', 'If the /etc/security/crypt.conf file does not support FIPS 140-2 approved cryptographic hashing algorithms, upgrade to at least the Solaris 10 8/07 release.

Edit the /etc/security/policy.conf file.
# vi /etc/security/policy.conf
Uncomment or add the CRYPT_ALGORITHMS_ALLOW line and set it to "5,6". Update the CRYPT_DEFAULT default line to be equal to 5 or 6. The following lines are acceptable.

CRYPT_ALGORITHMS_ALLOW=5,6
CRYPT_DEFAULT=6

Update passwords for all accounts with non-compliant password hashes.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36381r602746_chk'
  tag severity: 'medium'
  tag gid: 'V-226460'
  tag rid: 'SV-226460r603265_rule'
  tag stig_id: 'GEN000595'
  tag gtitle: 'SRG-OS-000073'
  tag fix_id: 'F-36345r602747_fix'
  tag 'documentable'
  tag legacy: ['SV-40790', 'V-22304']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
