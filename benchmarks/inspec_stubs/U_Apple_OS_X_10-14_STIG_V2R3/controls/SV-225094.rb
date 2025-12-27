control 'SV-225094' do
  title 'The macOS system must be configured with dedicated user accounts to decrypt the hard disk upon startup.'
  desc 'When "FileVault" and Multifactor Authentication are configured on the operating system, a dedicated user must be configured to ensure that the implemented Multifactor Authentication rules are enforced. If a dedicated user is not configured to decrypt the hard disk upon startup, the system will allow a user to bypass Multifactor Authentication rules during initial startup and first login.'
  desc 'check', 'Retrieve a list of authorized FileVault users:

# sudo fdesetup list

fvuser,85F41F44-22B3-6CB7-85A1-BCC2EA2B887A

If any unauthorized users are listed, this is a finding.

Verify that the defined FileVault users are disabled:

Note: This procedure must be ran for each defined FileVault User.

# sudo dscl . read /Users/<FileVault_User> AuthenticationAuthority | grep "DisabledUser"

AuthenticationAuthority: ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2,SRP-RFC5054-4096-SHA512-PBKDF2> ;Kerberosv5;;unlock@LKDC:SHA1.20BABA05A6B1A86A8C57581A8487596640A3E37B;LKDC:SHA1.20CEBE04A5B1D92D8C58189D8487593350D3A40A; ;SecureToken; DisabledUser

If the FileVault user is not disabled, this is a finding.

Verify that password forwarding has been disabled on the system:

# sudo defaults read /Library/Preferences/com.apple.loginwindow | grep "DisableFDEAutologin"

DisableFDEAutologin = 1;

If "DisableFDEAutologin" is not set to a value of "1", this is a finding.'
  desc 'fix', 'Create an authorized user account that will be used to unlock the disk on startup.

Disable the login ability of the newly created user account:

# sudo dscl . append /Users/<FileVault_User> AuthenticationAuthority DisabledUser

Disable FileVaults Auto-login feature:

# sudo defaults write /Library/Preferences/com.apple.loginwindow DisableFDEAutologin -bool YES

Remove all FileVault login access from each user account defined on the system that is not a designated FileVault user:

# sudo fdesetup remove -user <username>'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-26786r569431_chk'
  tag severity: 'medium'
  tag gid: 'V-225094'
  tag rid: 'SV-225094r610285_rule'
  tag stig_id: 'AOSX-14-000032'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26774r569432_fix'
  tag 'documentable'
  tag legacy: ['SV-104735', 'V-95597']
  tag cci: ['CCI-002143']
  tag nist: ['AC-2 (11)']
end
