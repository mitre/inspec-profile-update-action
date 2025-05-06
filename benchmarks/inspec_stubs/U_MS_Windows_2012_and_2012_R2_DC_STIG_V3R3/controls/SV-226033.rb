control 'SV-226033' do
  title 'Windows 2012/2012 R2 password for the built-in Administrator account must be changed at least annually or when a member of the administrative team leaves the organization.'
  desc %q(The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password. The password for the built-in Administrator account must be changed at least annually or when any member of the administrative team leaves the organization.

It is highly recommended to use Microsoft's Local Administrator Password Solution (LAPS). Domain-joined systems can configure this to occur more frequently. LAPS will change the password every "30" days by default. The AO still has the overall authority to use another equivalent capability to accomplish the check.)
  desc 'check', %q(Review the password last set date for the built-in Administrator account.

Domain controllers:

Open "Windows PowerShell".

Enter "Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like "*-500" | FL Name, SID, PasswordLastSet".

If the "PasswordLastSet" date is greater than one year old, this is a finding.

Member servers and standalone systems:

Open "Windows PowerShell" or "Command Prompt".

Enter 'Net User [account name] | Find /i "Password Last Set"', where [account name] is the name of the built-in administrator account.

(The name of the built-in Administrator account must be changed to something other than "Administrator" per STIG requirements.)

If the "PasswordLastSet" date is greater than one year old, this is a finding.)
  desc 'fix', "Change the built-in Administrator account password at least annually or whenever an administrator leaves the organization. More frequent changes are recommended.

It is highly recommended to use Microsoft's LAPS, which may be used on domain-joined member servers to accomplish this."
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27735r475422_chk'
  tag severity: 'medium'
  tag gid: 'V-226033'
  tag rid: 'SV-226033r794811_rule'
  tag stig_id: 'WN12-00-000007'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27723r794810_fix'
  tag 'documentable'
  tag legacy: ['SV-52942', 'V-14225']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
