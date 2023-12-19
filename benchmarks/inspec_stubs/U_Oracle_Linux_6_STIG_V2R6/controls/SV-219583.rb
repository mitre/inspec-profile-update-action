control 'SV-219583' do
  title 'The system must disable accounts after excessive login failures within a 15-minute interval.'
  desc 'Locking out user accounts after a number of incorrect attempts within a specific period of time prevents direct password guessing attacks.'
  desc 'check', 'To ensure the failed password attempt policy is configured correctly, run the following command:

$ grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth

For each file, the output should show "fail_interval=<interval-in-seconds>" where "interval-in-seconds" is 900 (15 minutes) or greater. If the "fail_interval" parameter is not set, the default setting of 900 seconds is acceptable. If that is not the case, this is a finding.'
  desc 'fix', 'Utilizing "pam_faillock.so", the "fail_interval" directive configures the system to lock out accounts after a number of incorrect logon attempts. Modify the content of both "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" as follows:

Add the following line immediately before the "pam_unix.so" statement in the "AUTH" section:

auth required pam_faillock.so preauth silent deny=3 unlock_time=900 fail_interval=900

Add the following line immediately after the "pam_unix.so" statement in the "AUTH" section:

auth [default=die] pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900

Add the following line immediately before the "pam_unix.so" statement in the "ACCOUNT" section:

account required pam_faillock.so

Note that any updates made to "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" may be overwritten by the "authconfig" program. The "authconfig" program should not be used.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-36263r602383_chk'
  tag severity: 'medium'
  tag gid: 'V-219583'
  tag rid: 'SV-219583r793840_rule'
  tag stig_id: 'OL6-00-000357'
  tag gtitle: 'SRG-OS-000329'
  tag fix_id: 'F-36227r602384_fix'
  tag 'documentable'
  tag legacy: ['V-50635', 'SV-64841']
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
