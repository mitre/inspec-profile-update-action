control 'SV-230762' do
  title 'The macOS system must be configured with dedicated user accounts to decrypt the hard disk upon startup.'
  desc 'When "FileVault" and Multifactor Authentication are configured on the operating system, a dedicated user must be configured to ensure that the implemented Multifactor Authentication rules are enforced. If a dedicated user is not configured to decrypt the hard disk upon startup, the system will allow a user to bypass Multifactor Authentication rules during initial startup and first login.'
  desc 'check', 'Retrieve a list of authorized FileVault users:

# sudo fdesetup list

fvuser,85F41F44-22B3-6CB7-85A1-BCC2EA2B887A

If any unauthorized users are listed, this is a finding.

Verify that the authorized FileVault users are marked as “DisabledUser”, preventing console logins:

Note: This procedure will need to be run for each authorized FileVault User.

# sudo dscl . read /Users/<FileVault_User> AuthenticationAuthority | grep "DisabledUser"

AuthenticationAuthority: ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2,SRP-RFC5054-4096-SHA512-PBKDF2> ;Kerberosv5;;unlock@LKDC:SHA1.20BABA05A6B1A86A8C57581A8487596640A3E37B;LKDC:SHA1.20CEBE04A5B1D92D8C58189D8487593350D3A40A; ;SecureToken; DisabledUser

If the FileVault user is not disabled, this is a finding.'
  desc 'fix', 'Create an authorized user account that will be used to unlock the disk on startup.

Disable the login ability of the newly created user account:

# sudo dscl . append /Users/<FileVault_User> AuthenticationAuthority DisabledUser

Remove all FileVault login access from each user account defined on the system that is not a designated FileVault user:

# sudo fdesetup remove -user <username>'
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33707r607173_chk'
  tag severity: 'medium'
  tag gid: 'V-230762'
  tag rid: 'SV-230762r599842_rule'
  tag stig_id: 'APPL-11-000032'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-33680r607557_fix'
  tag 'documentable'
  tag cci: ['CCI-002143']
  tag nist: ['AC-2 (11)']
end
