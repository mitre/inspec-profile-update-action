control 'SV-218081' do
  title 'The system must require administrator action to unlock an account locked by excessive failed login attempts.'
  desc 'Locking out user accounts after a number of incorrect attempts prevents direct password guessing attacks. Ensuring that an administrator is involved in unlocking locked accounts draws appropriate attention to such situations.'
  desc 'check', 'To ensure the failed password attempt policy is configured correctly, run the following command: 

# grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth

If the "unlock_time" parameter is set to a value other than "0", "never", or less than "900" on "auth" lines with the "pam_faillock.so" module, or is missing from these lines, this is a finding.

Note: The maximum configurable value for "unlock_time" is "604800".'
  desc 'fix', 'To configure the system to lock out accounts after a number of incorrect logon attempts and require an administrator to unlock the account using "pam_faillock.so", modify the content of both "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" as follows: 

Add the following line immediately before the "pam_unix.so" statement in the "AUTH" section: 

auth required pam_faillock.so preauth silent deny=3 unlock_time=900 fail_interval=900

Add the following line immediately after the "pam_unix.so" statement in the "AUTH" section: 

auth [default=die] pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900

Add the following line immediately before the "pam_unix.so" statement in the "ACCOUNT" section: 

account required pam_faillock.so

Note that any updates made to "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" may be overwritten by the "authconfig" program.  The "authconfig" program should not be used.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-36338r602612_chk'
  tag severity: 'medium'
  tag gid: 'V-218081'
  tag rid: 'SV-218081r603264_rule'
  tag stig_id: 'RHEL-06-000356'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36301r602613_fix'
  tag 'documentable'
  tag legacy: ['SV-50393', 'V-38592']
  tag cci: ['CCI-000047']
  tag nist: ['AC-7 b']
end
