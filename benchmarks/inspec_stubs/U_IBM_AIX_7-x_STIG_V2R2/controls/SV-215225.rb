control 'SV-215225' do
  title 'AIX must use Loadable Password Algorithm  (LPA) password hashing algorithm.'
  desc "The default legacy password hashing algorithm, crypt(), uses only the first 8 characters from the password string, meaning the user's password is truncated to eight characters. If the password is shorter than 8 characters, it is padded with zero bits on the right.

The crypt() is a modified DES algorithm that is vulnerable to brute force password guessing attacks and also to cracking the DES-hashing algorithm by using techniques such as pre-computation. 

With the Loadable Password Algorithm (LPA) framework release, AIX implemented a set of LPAs using MD5, SHA2, and Blowfish algorithms. These IBM proprietary password algorithms support a password longer than 8 characters and Unicode characters in passwords."
  desc 'check', 'From the command prompt, run the following command to check system wide password algorithm:

# lssec -f /etc/security/login.cfg -s usw -a pwd_algorithm
usw pwd_algorithm=ssha512

If the "pwd_algorithm" is not set to "ssha512", or "ssha256", this is a finding.'
  desc 'fix', %q(From the command prompt, run the following command to set system wide password algorithm to "ssha512" so that it supports passwords longer than 8-character:
# chsec -f /etc/security/login.cfg -s usw -a pwd_algorithm=ssha512

For each users who have hashed passwords in "/etc/security/passwd" file that does not start with "{ssha512}", run passwd commands to reset the users' passwords so that they have to change their passwords in the next login:
# passwd [user_name])
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16423r294126_chk'
  tag severity: 'high'
  tag gid: 'V-215225'
  tag rid: 'SV-215225r508663_rule'
  tag stig_id: 'AIX7-00-001128'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-16421r294127_fix'
  tag 'documentable'
  tag legacy: ['SV-101413', 'V-91315']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
