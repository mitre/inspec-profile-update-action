control 'SV-221677' do
  title 'The Oracle Linux operating system must be configured so that the PAM system service is configured to store only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text.'
  desc 'check', 'Verify the PAM system service is configured to store only encrypted representations of passwords. The strength of encryption that must be used to hash passwords for all accounts is SHA512.

Check that the system is configured to create SHA512 hashed passwords with the following command:

     # grep password /etc/pam.d/system-auth /etc/pam.d/password-auth

Outcome should look like following:
     /etc/pam.d/system-auth-ac:password sufficient pam_unix.so sha512 shadow try_first_pass use_authtok
     /etc/pam.d/password-auth:password sufficient pam_unix.so sha512 shadow try_first_pass use_authtok

If the "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" configuration files allow for password hashes other than SHA512 to be used, this is a finding.'
  desc 'fix', 'Configure the operating system to store only SHA512 encrypted representations of passwords.

Add the following line in "/etc/pam.d/system-auth":
pam_unix.so sha512 shadow try_first_pass use_authtok

Add the following line in "/etc/pam.d/password-auth":
pam_unix.so sha512 shadow try_first_pass use_authtok

Note: Per requirement OL07-00-010199, Oracle Linux 7 must be configured to not overwrite custom authentication configuration settings while using the authconfig utility, otherwise manual changes to the listed files will be overwritten whenever the authconfig utility is used.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23392r880670_chk'
  tag severity: 'medium'
  tag gid: 'V-221677'
  tag rid: 'SV-221677r880672_rule'
  tag stig_id: 'OL07-00-010200'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-23381r880671_fix'
  tag 'documentable'
  tag legacy: ['V-99095', 'SV-108199']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
