control 'SV-222433' do
  title 'The application administrator must follow an approved process to unlock locked user accounts.'
  desc 'Once a user account has been locked, it must be unlocked by an administrator.

An ISSM and ISSO approved process must be created and followed to ensure the user requesting access is properly authenticated prior to access being re-established.

The process must include having the user provide information only the user would know and having the administrator verify the accuracy of the information prior to unlocking the account. This means having the user provide this information when their account is created so the information can be referenced when they are locked out.    

The process utilized may be manual in nature, however it is recognized that password resets are a time consuming task. To minimize helpdesk resource constraints related to user lockout requests, procedures may be automated by administrators in order to unlock the account or reset the password.  

Authentication process examples include having the user provide personal information known only by the user and provided when the account was created and/or using Out-of-Band or side channel communication methods such as text messages to the users established cell phone number in order to provide a temporary password or token that can be used to logon once and reset the password.

The OWASP site provides an acceptable password reset process that can be used as a reference.  https://www.owasp.org/index.php/Forgot_Password_Cheat_Sheet.  

Automated procedures should follow industry standards and best practice for securely automating password reset/account unlocks and must be reviewed, tested, and then approved by the ISSM and ISSO.'
  desc 'check', 'Interview the application administrator and identify the approved process for unlocking user accounts.

The process may involve a manual or automated reset after the locked out user has identified themselves using standard user identification processes outlined in the vulnerability discussion.

If the admin does not unlock the account following the approved process, and if the process does not have documented ISSO and ISSM approvals, this is a finding.'
  desc 'fix', 'Create a standard approved process for unlocking locked application accounts which includes validating user identity prior to unlocking the account.

Use that process when unlocking application user accounts.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24103r493207_chk'
  tag severity: 'medium'
  tag gid: 'V-222433'
  tag rid: 'SV-222433r849433_rule'
  tag stig_id: 'APSC-DV-000540'
  tag gtitle: 'SRG-APP-000345'
  tag fix_id: 'F-24092r493208_fix'
  tag 'documentable'
  tag legacy: ['SV-83969', 'V-69347']
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
