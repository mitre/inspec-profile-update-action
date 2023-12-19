control 'SV-44865' do
  title 'The password hashes stored on the system must have been generated using a FIPS 140-2 approved cryptographic hashing algorithm.'
  desc 'Systems must employ cryptographic hashes for passwords using the SHA-2 family of algorithms or FIPS 140-2 approved successors.  The use of unapproved algorithms may result in weak password hashes more vulnerable to compromise.'
  desc 'check', "Check all password hashes in /etc/passwd or /etc/shadow begin with '$5$' or '$6$'.

Procedure:
# cut -d ':' -f2 /etc/passwd
# cut -d ':' -f2 /etc/shadow

Any password hashes present not beginning with '$5$' or '$6$', is a finding."
  desc 'fix', 'Change the passwords for all accounts using non-compliant password hashes. 

(This requires GEN000590 is already met.)'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42327r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22304'
  tag rid: 'SV-44865r1_rule'
  tag stig_id: 'GEN000595'
  tag gtitle: 'GEN000595'
  tag fix_id: 'F-38298r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
