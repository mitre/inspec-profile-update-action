control 'SV-254131' do
  title 'Nutanix AOS must enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

'
  desc 'check', 'Confirm that Nutanix AOS locks an account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes with the following command:

$ sudo grep pam_faillock.so /etc/pam.d/password-auth

auth        required      pam_faillock.so preauth silent audit deny=3 even_deny_root unlock_time=900 root_unlock_time=900 fail_interval=900
auth        [default=die] pam_faillock.so authfail audit deny=3 even_deny_root unlock_time=900 root_unlock_time=900 fail_interval=900

If the "deny" parameter is set to "0" or a value greater than "3" on both "auth" lines with the "pam_faillock.so" module, or is missing from these lines, this is a finding.

If the "even_deny_root" parameter is not set on both "auth" lines with the "pam_faillock.so" module, or is missing from these lines, this is a finding.

If the "fail_interval" parameter is set to "0" or is set to a value less than "900" on both "auth" lines with the "pam_faillock.so" module, or is missing from these lines, this is a finding.

If the "unlock_time" parameter is not set to "0", "never", or is set to a value less than "900" on both "auth" lines with the "pam_faillock.so" module, or is missing from these lines, this is a finding.

Note: The maximum configurable value for "unlock_time" is "604800".

If any line referencing the "pam_faillock.so" module is commented out, this is a finding.

$ sudo grep pam_faillock.so /etc/pam.d/system-auth

auth required pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=900
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=900
account required pam_faillock.so

If the "deny" parameter is set to "0" or a value greater than "3" on both "auth" lines with the "pam_faillock.so" module, or is missing from these lines, this is a finding.

If the "even_deny_root" parameter is not set on both "auth" lines with the "pam_faillock.so" module, or is missing from these lines, this is a finding.

If the "fail_interval" parameter is set to "0" or is set to a value less than "900" on both "auth" lines with the "pam_faillock.so" module, or is missing from these lines, this is a finding.

If the "unlock_time" parameter is not set to "0", "never", or is set to a value less than "900" on both "auth" lines with the "pam_faillock.so" module or is missing from these lines, this is a finding.

Note: The maximum configurable value for "unlock_time" is "604800".

If any line referencing the "pam_faillock.so" module is commented out, this is a finding.'
  desc 'fix', 'Configure the pam.d modules to comply with the locking an account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes with the following command:

1. Enable high-strength passwords:
$ ncli cluster edit-cvm-security-params enable-high-strength-password=true

2. After enabling the high-strength passwords, the system will process the salt stack to enable the DoD versions of the pam.d files. Recheck the Check Text for compliance.  

To run the salt command manually to enable the pam.d auth files, run the following command (high-strength passwords must be set to true):
$ sudo salt-call state.sls security/CVM/pamCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57616r846479_chk'
  tag severity: 'medium'
  tag gid: 'V-254131'
  tag rid: 'SV-254131r846481_rule'
  tag stig_id: 'NUTX-OS-000220'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-57567r846480_fix'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
end
