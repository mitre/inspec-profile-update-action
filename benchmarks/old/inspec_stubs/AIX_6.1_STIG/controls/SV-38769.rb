control 'SV-38769' do
  title 'The system must enforce the entire password during authentication.'
  desc "Some common password hashing schemes only process the first eight characters of a user's password, which reduces the effective strength of the password."
  desc 'check', 'Verify no password hashes in /etc/passwd.
# cat /etc/passwd | cut -f2,2 -d":"

If there are password hashes present,  this is a finding.

Verify no password hashes in the /etc/security/passwd file begin with the characters other than {ssha256} or {ssha512}

#cat /etc/security/passwd | grep password
If there are password hashes that do not begin with {ssha256} or {ssha512},  this is a finding.'
  desc 'fix', 'Configure the system to enforce the correctness of the entire password during authentication.

Configure the system to use sha password hashing.
#chsec -f /etc/security/login.cfg -s usw -a pwd_algorithm=ssha256'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36696r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22302'
  tag rid: 'SV-38769r1_rule'
  tag stig_id: 'GEN000585'
  tag gtitle: 'GEN000585'
  tag fix_id: 'F-33345r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
