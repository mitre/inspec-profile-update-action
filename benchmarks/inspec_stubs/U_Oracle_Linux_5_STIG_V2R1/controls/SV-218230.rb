control 'SV-218230' do
  title 'The password hashes stored on the system must have been generated using a FIPS 140-2 approved cryptographic hashing algorithm.'
  desc 'Systems must employ cryptographic hashes for passwords using the SHA-2 family of algorithms or FIPS 140-2 approved successors.  The use of unapproved algorithms may result in weak password hashes more vulnerable to compromise.'
  desc 'check', "Check all password hashes in /etc/passwd or /etc/shadow begin with '$5$' or '$6$'.

Procedure:
# cut -d ':' -f2 /etc/passwd
# cut -d ':' -f2 /etc/shadow

Any password hashes present not beginning with '$5$' or, '$6$' is a finding.  Any entries showing only NP, LK, or x are not findings."
  desc 'fix', 'Change the passwords for all accounts using non-compliant password hashes. 

(This requires GEN000590 is already met.)'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19705r554027_chk'
  tag severity: 'medium'
  tag gid: 'V-218230'
  tag rid: 'SV-218230r603259_rule'
  tag stig_id: 'GEN000595'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-19703r554028_fix'
  tag 'documentable'
  tag legacy: ['V-22304', 'SV-63949']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
