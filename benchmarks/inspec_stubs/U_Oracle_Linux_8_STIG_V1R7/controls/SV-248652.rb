control 'SV-248652' do
  title 'OL 8 systems below version 8.2 must automatically lock an account when three unsuccessful logon attempts occur.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account. 
 
OL 8 can use the "pam_faillock.so" for this purpose. Note that manual changes to the listed files may be overwritten by the "authselect" program. 
 
From "Pam_Faillock" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable, a different tally directory must be set with the "dir" option.

'
  desc 'check', 'Verify the system locks an account after three unsuccessful logon attempts with the following commands. 
 
Note: If the System Administrator demonstrates the use of an approved centralized account management method that locks an account after three unsuccessful logon attempts within a period of 15 minutes, this requirement is not applicable. 
 
Note: This check applies to OL versions 8.0 and 8.1. If the system is OL version 8.2 or newer, this check is not applicable. 
 
$ sudo grep pam_faillock.so /etc/pam.d/password-auth 
 
auth required pam_faillock.so preauth dir=/var/log/faillock silent audit deny=3 even_deny_root fail_interval=900 unlock_time=0 
auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0 
account required pam_faillock.so 
 
If the "deny" option is not set to "3" or less (but not "0") on the "preauth" line with the "pam_faillock.so" module or is missing from this line, this is a finding. 
 
If any line referencing the "pam_faillock.so" module is commented out, this is a finding. 
 
$ sudo grep pam_faillock.so /etc/pam.d/system-auth 
 
auth required pam_faillock.so preauth dir=/var/log/faillock silent audit deny=3 even_deny_root fail_interval=900 unlock_time=0 
auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0 
account required pam_faillock.so 
 
If the "deny" option is not set to "3" or less (but not "0") on the "preauth" line with the "pam_faillock.so" module or is missing from this line, this is a finding. 
 
If any line referencing the "pam_faillock.so" module is commented out, this is a finding.'
  desc 'fix', 'Add/modify the appropriate sections of the "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" files to match the following lines: 
 
auth required pam_faillock.so preauth dir=/var/log/faillock silent audit deny=3 even_deny_root fail_interval=900 unlock_time=0 
auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0 
account required pam_faillock.so 
 
The "sssd" service must be restarted for the changes to take effect. To restart the "sssd" service, run the following command: 
 
$ sudo systemctl restart sssd.service'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52086r779520_chk'
  tag severity: 'medium'
  tag gid: 'V-248652'
  tag rid: 'SV-248652r853775_rule'
  tag stig_id: 'OL08-00-020010'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-52040r779521_fix'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
end
