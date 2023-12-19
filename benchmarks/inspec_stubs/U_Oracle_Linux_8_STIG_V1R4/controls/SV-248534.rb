control 'SV-248534' do
  title 'OL 8 must employ FIPS 140-2 approved cryptographic hashing algorithms for all stored passwords.'
  desc 'The system must use a strong hashing algorithm to store the password. 
 
Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Confirm that the interactive user account passwords are using a strong password hash with the following command: 
 
$ sudo cut -d: -f2 /etc/shadow 
 
$6$kcOnRq/5$NUEYPuyL.wghQwWssXRcLRFiiru7f5JPV6GaJhNC2aK5F3PZpE/BCCtwrxRc/AInKMNX3CdMw11m9STiql12f/ 
 
Password hashes "!" or "*" indicate inactive accounts not available for logon and are not evaluated.  
 
If any interactive user password hash does not begin with "$6$", this is a finding.'
  desc 'fix', 'Lock all interactive user accounts not using SHA-512 hashing until the passwords can be regenerated with SHA-512.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51968r779166_chk'
  tag severity: 'medium'
  tag gid: 'V-248534'
  tag rid: 'SV-248534r779168_rule'
  tag stig_id: 'OL08-00-010120'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-51922r779167_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
