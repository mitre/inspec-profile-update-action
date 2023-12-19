control 'SV-230335' do
  title 'RHEL 8 must automatically lock an account when three unsuccessful logon attempts occur during a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to centralize the configuration of the pam_faillock.so module.  Also introduced is a "local_users_only" option that will only track failed user authentication attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP, etc.) users to allow the centralized platform to solely manage user lockout.

From "faillock.conf" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the "dir" option.

'
  desc 'check', %q(Check that the system locks an account after three unsuccessful logon attempts within a period of 15 minutes with the following commands:

Note: This check applies to RHEL versions 8.2 or newer, if the system is RHEL version 8.0 or 8.1, this check is not applicable.

Verify the pam_faillock.so module is present in the "/etc/pam.d/system-auth" and " /etc/pam.d/password-auth" files:

$ sudo grep pam_faillock.so /etc/pam.d/system-auth /etc/pam.d/password-auth

/etc/pam.d/system-auth:auth               required                                     pam_faillock.so preauth
/etc/pam.d/system-auth:auth               required                                     pam_faillock.so authfail
/etc/pam.d/system-auth:account        required                                     pam_faillock.so
/etc/pam.d/password-auth:auth          required                                     pam_faillock.so preauth
/etc/pam.d/password-auth:auth          required                                     pam_faillock.so authfail
/etc/pam.d/password-auth:account   required                                     pam_faillock.so preauth

If the pam_failllock.so module is not present in the "/etc/pam.d/system-auth" and " /etc/pam.d/password-auth" files, this is a finding.

Verify the "/etc/security/faillock.conf" file is configured to lock an account after three unsuccessful logon attempts within 15 minutes:

$ sudo grep 'fail_interval =' /etc/security/faillock.conf

fail_interval = 900

If the "fail_interval" option is not set to "900" or less (but not "0"), is missing or commented out, this is a finding.)
  desc 'fix', 'Configure the operating system to lock an account when three unsuccessful logon attempts occur in 15 minutes.

Add/Modify the appropriate sections of the "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" files to match the following lines:

auth required pam_faillock.so preauth
auth required pam_faillock.so authfail
account required pam_faillock.so

Add/Modify the "/etc/security/faillock.conf" file to match the following line:

fail_interval = 900'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-33004r567751_chk'
  tag severity: 'medium'
  tag gid: 'V-230335'
  tag rid: 'SV-230335r627750_rule'
  tag stig_id: 'RHEL-08-020013'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-32979r567752_fix'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
