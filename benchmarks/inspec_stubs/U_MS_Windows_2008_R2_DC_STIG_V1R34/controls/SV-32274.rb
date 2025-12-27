control 'SV-32274' do
  title 'The Windows 2008 R2 password for the built-in Administrator account must be changed at least annually or when a member of the administrative team leaves the organization.'
  desc "The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password. The password for the built-in Administrator account must be changed at least annually or when any member of the administrative team leaves the organization.

Organizations that use an automated tool, such as Microsoft's Local Administrator Password Solution (LAPS), on domain-joined systems can configure this to occur more frequently. LAPS will change the password every 30 days by default."
  desc 'check', %q(Review the password last set date for the built-in Administrator account.

Domain controllers:

Open "Windows PowerShell".

Enter "Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like "*-500" | FL Name, SID, PasswordLastSet".

If the "PasswordLastSet" date is greater than one year old, this is a finding.

Member servers and standalone systems:

Open "Windows PowerShell" or "Command Prompt".

Enter 'Net User [account name] | Find /i "Password Last Set"', where [account name] is the name of the built-in Administrator account.

(The name of the built-in Administrator account must be changed to something other than "Administrator" per STIG requirements.)

If the "PasswordLastSet" date is greater than one year old, this is a finding.)
  desc 'fix', "Change the built-in Administrator account password at least annually or whenever an administrator leaves the organization. More frequent changes are recommended.

Automated tools, such as Microsoft's LAPS, may be used on domain-joined member servers to accomplish this."
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-80173r2_chk'
  tag severity: 'medium'
  tag gid: 'V-14225'
  tag rid: 'SV-32274r2_rule'
  tag gtitle: 'Administrator Account Password Changes'
  tag fix_id: 'F-87305r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
