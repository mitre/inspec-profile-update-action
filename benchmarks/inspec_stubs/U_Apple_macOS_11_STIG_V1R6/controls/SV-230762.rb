control 'SV-230762' do
  title 'The macOS system must be configured with dedicated user accounts to decrypt the hard disk upon startup.'
  desc 'When "FileVault" and Multifactor Authentication are configured on the operating system, a dedicated user must be configured to ensure that the implemented Multifactor Authentication rules are enforced. If a dedicated user is not configured to decrypt the hard disk upon startup, the system will allow a user to bypass Multifactor Authentication rules during initial startup and first login.'
  desc 'check', %q(Retrieve a list of authorized FileVault users:
$ sudo fdesetup list

fvuser,85F41F44-22B3-6CB7-85A1-BCC2EA2B887A

If any unauthorized users are listed, this is a finding.

Verify that the shell for authorized FileVault users is set to “/usr/bin/false”, which prevents console logins:
$ sudo dscl . read /Users/<FileVault_User> UserShell

UserShell: /usr/bin/false

If the FileVault users' shell is not set to "/usr/bin/false", this is a finding.)
  desc 'fix', 'Note: In previous versions of macOS, this setting was implemented differently. Systems that used the previous method should prepare the system for the new method by creating a new unlock user, verifying its ability to unlock FileVault after reboot, then deleting the old FileVault unlock user. 

Disable the login ability of the newly created user account:
$ sudo /usr/bin/dscl . change /Users/<FileVault_User> UserShell </path/to/current/shell> /usr/bin/false

Remove all FileVault login access from each user account defined on the system that is not a designated FileVault user:
$ sudo fdesetup remove -user <username>'
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33707r802376_chk'
  tag severity: 'medium'
  tag gid: 'V-230762'
  tag rid: 'SV-230762r802378_rule'
  tag stig_id: 'APPL-11-000032'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-33680r802377_fix'
  tag 'documentable'
  tag cci: ['CCI-002143']
  tag nist: ['AC-2 (11)']
end
