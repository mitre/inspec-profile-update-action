control 'SV-215230' do
  title 'The password hashes stored on AIX system must have been generated using a FIPS 140-2 approved cryptographic hashing algorithm.'
  desc 'Systems must employ cryptographic hashes for passwords using the SHA-2 family of algorithms or FIPS 140-2 approved successors. The use of unapproved algorithms may result in weak password hashes that are more vulnerable to compromise.'
  desc 'check', 'Verify that the system wide password algorithm is set to {ssha256} or {ssha512} by running the following command:

# lssec -f /etc/security/login.cfg -s usw -a pwd_algorithm
usw pwd_algorithm=ssha512

If the "pwd_algorithm" is not set to "ssha256" or "ssha512", this is a finding.

Verify no password hashes in /etc/passwd by running the following command: 

# cat /etc/passwd | cut -f2,2 -d":" 
!
!
!
!
*
*
*
*

If there are password hashes present, this is a finding. 

Verify all password hashes in "/etc/security/passwd" begin with {ssha256} or {ssha512} by running commands: 
 
# cat /etc/security/passwd | grep password 
        password = {ssha512}06$e58YOawe/7UhChqh$hZEWlP4040jarX1NeOujmcxd.7qerUvjW9lM9djJsDITtdjFvVpLX.r04xieOWrbH0qb0SJJ98a0tmgZBzPP..
        password = {ssha512}06$Y6ztvMxKGdITxPex$B81/GDTEPt0xwp.BX1VhY9mAPaWHXdNoLI9D0T6dBExgo6r87X0etnfjxWODT73.udrbAY.F4HzaBR68lN5/..
        password = {ssha512}06$iIXQQqs.mdGpC9Wu$cXSajikWYKAUacbF50FNlFgYYSgTklGf4uhXb1J/GyBGF5j5aWa4YG5Ah2uaAHv/Jmbmx.7yBm8iXz9Pz1LM..
        password = {ssha512}06$3Sw24rPVdqDFFCIl$d1dZs7GYmTXnD9i270SxozIBxN0pqq/bNn0YbyKeDq0o6Y.j9qfkeH373DwkHBWgrifNcgj/K0pVyzjMg6QN..

If any password hashes are present not beginning with {ssha256} or {ssha512}, this is a finding.'
  desc 'fix', 'Set the system wide password algorithm to "ssha256" or "ssha512" by running the following command:

# chsec -f /etc/security/login.cfg -s usw -a pwd_algorithm=ssha512

Change the passwords for all accounts using non-compliant password hashes by running the following command: 

$ passwd [user_name]'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16428r294141_chk'
  tag severity: 'medium'
  tag gid: 'V-215230'
  tag rid: 'SV-215230r508663_rule'
  tag stig_id: 'AIX7-00-001134'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16426r294142_fix'
  tag 'documentable'
  tag legacy: ['SV-101671', 'V-91573']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
