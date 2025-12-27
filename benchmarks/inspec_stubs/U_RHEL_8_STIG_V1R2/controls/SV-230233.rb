control 'SV-230233' do
  title 'RHEL 8 must employ FIPS 140-2 approved cryptographic hashing algorithms for all created passwords.'
  desc 'The system must use a strong hashing algorithm to store the password. The system must use a sufficient number of hashing rounds to ensure the required level of entropy.

Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Check that a minimum number of hash rounds is configured by running the following commands:

$ sudo grep rounds /etc/pam.d/password-auth

password sufficient pam_unix.so sha512 rounds=5000

$ sudo grep rounds /etc/pam.d/system-auth

password sufficient pam_unix.so sha512 rounds=5000

If "rounds" has a value below "5000", or is commented out in either file, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to encrypt all stored passwords with a strong cryptographic hash.

Edit/modify the following line in the "/etc/pam.d/password-auth" and "etc/pam.d/system-auth" files and set "rounds" to a value no lower than "5000":

password sufficient pam_unix.so sha512 rounds=5000'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-32902r567445_chk'
  tag severity: 'medium'
  tag gid: 'V-230233'
  tag rid: 'SV-230233r627750_rule'
  tag stig_id: 'RHEL-08-010130'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-32877r567446_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
