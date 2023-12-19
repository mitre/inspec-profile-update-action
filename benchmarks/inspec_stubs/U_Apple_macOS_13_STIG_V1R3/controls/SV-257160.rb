control 'SV-257160' do
  title 'The macOS system must be configured with dedicated user accounts to decrypt the hard disk upon startup.'
  desc 'When "FileVault" and Multifactor Authentication are configured on the operating system, a dedicated user must be configured to ensure that the implemented Multifactor Authentication rules are enforced. If a dedicated user is not configured to decrypt the hard disk upon startup, the system will allow a user to bypass Multifactor Authentication rules during initial startup and first login.'
  desc 'check', %q(Verify the macOS system is configured with dedicated user accounts to decrypt the hard disk upon startup with the following command:

/usr/bin/sudo /usr/bin/fdesetup list

fvuser,85F41F44-22B3-6CB7-85A1-BCC2EA2B887A

If any unauthorized users are listed, this is a finding.

Verify that the shell for authorized FileVault users is set to "/usr/bin/false" to prevent console logons:

/usr/bin/sudo /usr/bin/dscl . read /Users/<FileVault_User> UserShell

UserShell: /usr/bin/false

If the FileVault users' shell is not set to "/usr/bin/false", this is a finding.)
  desc 'fix', 'Configure the macOS system with a dedicated user account to decrypt the hard disk at startup and disable the logon ability of the newly created user account with the following commands:

/usr/bin/sudo /usr/bin/fdesetup add -user <username>

/usr/bin/sudo /usr/bin/dscl . change /Users/<FileVault_User> UserShell </path/to/current/shell> /usr/bin/false

Remove all FileVault logon access from each user account defined on the system that is not a designated FileVault user:

/usr/bin/sudo /usr/bin/fdesetup remove -user <username>'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60845r905111_chk'
  tag severity: 'medium'
  tag gid: 'V-257160'
  tag rid: 'SV-257160r905113_rule'
  tag stig_id: 'APPL-13-000032'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60786r905112_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
