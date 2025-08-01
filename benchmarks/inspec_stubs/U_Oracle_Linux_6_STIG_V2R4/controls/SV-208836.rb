control 'SV-208836' do
  title 'The system must disable accounts after three consecutive unsuccessful logon attempts.'
  desc 'Locking out user accounts after a number of incorrect attempts prevents direct password guessing attacks.'
  desc 'check', 'To ensure the failed password attempt policy is configured correctly, run the following command:

# grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth

The output should show "deny=3" for both files.
If that is not the case, this is a finding.'
  desc 'fix', 'To configure the system to lock out accounts after a number of incorrect logon attempts using "pam_faillock.so", modify the content of both "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" as follows:

Add the following line immediately before the "pam_unix.so" statement in the "AUTH" section:

auth required pam_faillock.so preauth silent deny=3 unlock_time=900 fail_interval=900

Add the following line immediately after the "pam_unix.so" statement in the "AUTH" section:

auth [default=die] pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900

Add the following line immediately before the "pam_unix.so" statement in the "ACCOUNT" section:

account required pam_faillock.so

Note that any updates made to "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" may be overwritten by the "authconfig" program. The "authconfig" program should not be used.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-36260r602374_chk'
  tag severity: 'medium'
  tag gid: 'V-208836'
  tag rid: 'SV-208836r603263_rule'
  tag stig_id: 'OL6-00-000061'
  tag gtitle: 'SRG-OS-000021'
  tag fix_id: 'F-36224r602375_fix'
  tag 'documentable'
  tag legacy: ['SV-65127', 'V-50921']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
