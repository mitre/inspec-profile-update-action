control 'SV-221691' do
  title 'The Oracle Linux operating system must lock the associated account after three unsuccessful root logon attempts are made within a 15-minute period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.

'
  desc 'check', 'Verify the operating system automatically locks the root account for a minimum of 15 minutes when three unsuccessful logon attempts in 15 minutes are made.

# grep pam_faillock.so /etc/pam.d/password-auth
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=900 
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=900 
account required pam_faillock.so

If the "even_deny_root" setting is not defined on both lines with the "pam_faillock.so" module, is commented out, or is missing from a line, this is a finding.

# grep pam_faillock.so /etc/pam.d/system-auth
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=900 
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=900
account required pam_faillock.so

If the "even_deny_root" setting is not defined on both lines with the "pam_faillock.so" module, is commented out, or is missing from a line, this is a finding.'
  desc 'fix', 'Configure the operating system to automatically lock the root account, for a minimum of 15 minutes, when three unsuccessful logon attempts in 15 minutes are made.

Modify the first three lines of the auth section and the first line of the account section of the "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" files to match the following lines:

auth required pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=900
auth sufficient pam_unix.so try_first_pass
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=900
account required pam_faillock.so

Note: Manual changes to the listed files may be overwritten by the "authconfig" program. The "authconfig" program should not be used to update the configurations listed in this requirement.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23406r792788_chk'
  tag severity: 'medium'
  tag gid: 'V-221691'
  tag rid: 'SV-221691r853663_rule'
  tag stig_id: 'OL07-00-010330'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-23395r792789_fix'
  tag satisfies: ['SRG-OS-000329-GPOS-00128', 'SRG-OS-000021-GPOS-00005']
  tag 'documentable'
  tag legacy: ['V-99121', 'SV-108225']
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
