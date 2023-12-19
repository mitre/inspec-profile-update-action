control 'SV-248653' do
  title 'OL 8 systems, versions 8.2 and above, must automatically lock an account when three unsuccessful logon attempts occur.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account. 
 
In OL 8.2, the "/etc/security/faillock.conf" file was incorporated to centralize the configuration of the "pam_faillock.so" module. Also introduced is a "local_users_only" option that will only track failed user authentication attempts for local users in "/etc/passwd" and ignore centralized (AD, IdM, LDAP, etc.) users to allow the centralized platform to solely manage user lockout. 
 
From "faillock.conf" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable, a different tally directory must be set with the "dir" option.

'
  desc 'check', %q(Note: This check applies to OL versions 8.2 or newer. If the system is OL version 8.0 or 8.1, this check is not applicable. 
 
Verify the "/etc/security/faillock.conf" file is configured to lock an account after three unsuccessful logon attempts: 
 
$ sudo grep 'deny =' /etc/security/faillock.conf 
 
deny = 3 
 
If the "deny" option is not set to "3" or less (but not "0") or is missing or commented out, this is a finding.)
  desc 'fix', 'Configure OL 8 to lock an account when three unsuccessful logon attempts occur. 
 
Add/modify the "/etc/security/faillock.conf" file to match the following line: 
 
deny = 3'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52087r779523_chk'
  tag severity: 'medium'
  tag gid: 'V-248653'
  tag rid: 'SV-248653r779525_rule'
  tag stig_id: 'OL08-00-020011'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-52041r779524_fix'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
end
