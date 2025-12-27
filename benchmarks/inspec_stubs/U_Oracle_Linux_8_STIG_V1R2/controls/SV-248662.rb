control 'SV-248662' do
  title 'OL 8 systems below version 8.2 must log user name information when unsuccessful logon attempts occur.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account. 
 
OL 8 can use the "pam_faillock.so" for this purpose. Note that manual changes to the listed files may be overwritten by the "authselect" program. 
 
From "Pam_Faillock" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable, a different tally directory must be set with the "dir" option.

'
  desc 'check', 'Verify the system logs user name information when unsuccessful logon attempts occur with the following commands. 
 
Note: If the System Administrator demonstrates the use of an approved centralized account management method that locks an account after three unsuccessful logon attempts within a period of 15 minutes, this requirement is not applicable. 
 
Note: This check applies to OL versions 8.0 and 8.1. If the system is OL version 8.2 or newer, this check is not applicable. 
 
$ sudo grep pam_faillock.so /etc/pam.d/password-auth 
 
auth required pam_faillock.so preauth dir=/var/log/faillock silent audit deny=3 even_deny_root fail_interval=900 unlock_time=0 
auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0 
account required pam_faillock.so 
 
If the "audit" option is missing from the "preauth" line with the "pam_faillock.so" module, this is a finding. 
 
$ sudo grep pam_faillock.so /etc/pam.d/system-auth 
 
auth required pam_faillock.so preauth dir=/var/log/faillock silent audit deny=3 even_deny_root fail_interval=900 unlock_time=0 
auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0 
account required pam_faillock.so 
 
If the "audit" option is missing from the "preauth" line with the "pam_faillock.so" module, this is a finding.'
  desc 'fix', 'Configure the operating system to log user name information when unsuccessful logon attempts occur. 
 
Add/modify the appropriate sections of the "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" files to match the following lines: 
 
auth required pam_faillock.so preauth dir=/var/log/faillock silent audit deny=3 even_deny_root fail_interval=900 unlock_time=0 
auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0 
account required pam_faillock.so 
 
The "sssd" service must be restarted for the changes to take effect. To restart the "sssd" service, run the following command: 
 
$ sudo systemctl restart sssd.service'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52096r779550_chk'
  tag severity: 'medium'
  tag gid: 'V-248662'
  tag rid: 'SV-248662r779552_rule'
  tag stig_id: 'OL08-00-020020'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-52050r779551_fix'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
end
