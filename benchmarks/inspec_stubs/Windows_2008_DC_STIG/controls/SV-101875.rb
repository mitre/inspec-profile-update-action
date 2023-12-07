control 'SV-101875' do
  title 'The password for the krbtgt account on a domain must be reset at least every 180 days.'
  desc 'The krbtgt account acts as a service account for the Kerberos Key Distribution Center (KDC) service. The account and password are created when a domain is created and the password is typically not changed. If the krbtgt account is compromised, attackers can create valid Kerberos Ticket Granting Tickets (TGT).

The password must be changed twice to effectively remove the password history. Changing once, waiting for replication to complete and changing again reduces the risk of issues. Changing twice in rapid succession forces clients to re-authenticate (including application services) but is desired if a compromise is suspected.'
  desc 'check', 'This requirement is applicable to domain controllers; it is NA for other systems.

Open "Windows PowerShell".

Enter "Get-ADUser krbtgt -Property PasswordLastSet".

If the "PasswordLastSet" date is more than 180 days old, this is a finding.'
  desc 'fix', 'Reset the password for the krbtgt account a least every 180 days. The password must be changed twice to effectively remove the password history. Changing once, waiting for replication to complete and changing again reduces the risk of issues. Changing twice in rapid succession forces clients to re-authenticate (including application services) but is desired if a compromise is suspected.

PowerShell scripts are available to accomplish this such as at the following link:
https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51

Open "Active Directory Users and Computers" (available from various menus or run "dsa.msc").

Select "Advanced Features" in the "View" menu if not previously selected.

Select the "Users" node.

Right click on the krbtgt account and select "Reset password".

Enter a password that meets password complexity requirements.

Clear the "User must change password at next logon" check box.

The system will automatically change this to a system generated complex password.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-90931r1_chk'
  tag severity: 'medium'
  tag gid: 'V-91777'
  tag rid: 'SV-101875r1_rule'
  tag stig_id: 'WINAD-000015-DC_2008'
  tag gtitle: 'WINAD-000015-DC'
  tag fix_id: 'F-97975r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
