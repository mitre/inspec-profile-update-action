control 'SV-252957' do
  title 'TOSS must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes occur.'
  desc "By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.

Due to the scale of HPC systems and the number of users in question, it is impractical to require an administrator to unlock the user's account manually. Strong controls around automatic lock out, and typical (though not universal) use of strong MFA to enter an HPC system mitigate the concerns of a brute force attack being successful."
  desc 'check', %q(Check that the system locks an account after three unsuccessful logon attempts within a period of 15 minutes until released by an administrator with the following commands.

Note: If a centralized authentication platform (AD, IdM, LDAP, etc) is utilized for authentication, then this requirement is not applicable, to allow the centralized platform to solely manage user lockout.

Verify the pam_faillock.so module is present in the "/etc/pam.d/system-auth" and " /etc/pam.d/password-auth" files:

$ sudo grep pam_faillock.so /etc/pam.d/system-auth /etc/pam.d/password-auth

/etc/pam.d/system-auth:auth required pam_faillock.so preauth
/etc/pam.d/system-auth:auth required pam_faillock.so authfail
/etc/pam.d/system-auth:account required pam_faillock.so
/etc/pam.d/password-auth:auth required pam_faillock.so preauth
/etc/pam.d/password-auth:auth required pam_faillock.so authfail
/etc/pam.d/password-auth:account required pam_faillock.so preauth

If the pam_failllock.so module is not present in the "/etc/pam.d/system-auth" and " /etc/pam.d/password-auth" files, this is a finding.

Verify the "/etc/security/faillock.conf" file is configured to lock an account until released by an administrator after three unsuccessful logon attempts:

$ sudo grep 'unlock_time =' /etc/security/faillock.conf
unlock_time = 0

If the "unlock_time" option is not set to "0", is missing or commented out, this is a finding.)
  desc 'fix', 'Configure the operating system to lock an account until released by an administrator when three unsuccessful logon attempts occur in 15 minutes.

Add and/or modify the appropriate sections of the "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" files to match the following lines:

auth required pam_faillock.so preauth
auth required pam_faillock.so authfail
account required pam_faillock.so

Add and/or modify the "/etc/security/faillock.conf" file to match the following line:

unlock_time = 0'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56410r824193_chk'
  tag severity: 'medium'
  tag gid: 'V-252957'
  tag rid: 'SV-252957r824195_rule'
  tag stig_id: 'TOSS-04-020170'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-56360r824194_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
