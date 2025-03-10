control 'SV-217897' do
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

Note that any updates made to "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" may be overwritten by the "authconfig" program.  The "authconfig" program should not be used.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-36335r602603_chk'
  tag severity: 'medium'
  tag gid: 'V-217897'
  tag rid: 'SV-217897r603264_rule'
  tag stig_id: 'RHEL-06-000061'
  tag gtitle: 'SRG-OS-000021'
  tag fix_id: 'F-36298r602604_fix'
  tag 'documentable'
  tag legacy: ['V-38573', 'SV-50374']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
