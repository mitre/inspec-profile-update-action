control 'SV-25951' do
  title 'The password hashes stored on the system must have been generated using a FIPS 140-2 approved cryptographic hashing algorithm.'
  desc 'Systems must employ cryptographic hashes for passwords using the SHA-2 family of algorithms or FIPS 140-2 approved successors. The use of unapproved algorithms may result in weak password hashes more vulnerable to compromise.'
  desc 'check', "Determine if any password hashes stored on the system were not generated using a FIPS 140-2 approved cryptographic hashing algorithm.

Generally, a hash prefix of $5$ or $6$ indicates approved hashes. Consult OS documentation to determine the actual prefixes or other methods used by the OS to indicate approved hash algorithms.

Procedure:
# cut -d ':' -f2 /etc/passwd
# cut -d ':' -f2 /etc/shadow

If any password hashes are present not beginning with $5$ or $6$, or have other indications of the use of approved hash algorithms consistent with vendor documentation, this is a finding."
  desc 'fix', 'Replace password hashes with those created using a FIPS 140-2 approved cryptographic hashing algorithm.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29095r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22304'
  tag rid: 'SV-25951r1_rule'
  tag stig_id: 'GEN000595'
  tag gtitle: 'GEN000595'
  tag fix_id: 'F-26094r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1, IAIA-1, IAIA-2'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
