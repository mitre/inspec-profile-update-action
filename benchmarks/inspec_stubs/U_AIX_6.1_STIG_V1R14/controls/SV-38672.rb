control 'SV-38672' do
  title 'The password hashes stored on the system must have been generated using a FIPS 140-2 approved cryptographic hashing algorithm.'
  desc 'Systems must employ cryptographic hashes for passwords using the SHA-2 family of algorithms or FIPS 140-2 approved successors. The use of unapproved algorithms may result in weak password hashes that are more vulnerable to compromise.'
  desc 'check', 'Verify no password hashes in /etc/passwd.
# cat /etc/passwd | cut -f2,2 -d":"

If there are password hashes present, this is a finding.

Verify all password hashes in /etc/security/passwd begin with {ssha256} or {ssha512}.

Procedure:
# cat /etc/passwd | cut -f2,2 -d ":"

# cat /etc/security/passwd | grep password

If any password hashes are present not beginning with {ssha256} or {ssha512}, this is a finding.'
  desc 'fix', 'Change the passwords for all accounts using non-compliant password hashes. 

# passwd account
OR
# smitty passwd

(This requires that GEN000590 is already met.)'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36894r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22304'
  tag rid: 'SV-38672r1_rule'
  tag stig_id: 'GEN000595'
  tag gtitle: 'GEN000595'
  tag fix_id: 'F-32015r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1, IAIA-1, IAIA-2'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
