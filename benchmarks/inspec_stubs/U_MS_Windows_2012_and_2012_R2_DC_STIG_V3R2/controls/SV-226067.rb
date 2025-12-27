control 'SV-226067' do
  title 'The Kerberos user ticket lifetime must be limited to 10 hours or less.'
  desc "In Kerberos, there are 2 types of tickets: Ticket Granting Tickets (TGTs) and Service Tickets.  Kerberos tickets have a limited lifetime so the time an attacker has to implement an attack is limited.  This policy controls how long TGTs can be renewed.  With Kerberos, the user's initial authentication to the domain controller results in a TGT which is then used to request Service Tickets to resources.  Upon startup, each computer gets a TGT before requesting a service ticket to the domain controller and any other computers it needs to access.  For services that startup under a specified user account, users must always get a TGT first, then get Service Tickets to all computers and services accessed."
  desc 'check', 'Verify the following is configured in the Default Domain Policy.

Open "Group Policy Management".
Navigate to "Group Policy Objects" in the Domain being reviewed (Forest > Domains > Domain). 
Right click on the "Default Domain Policy".
Select Edit.
Navigate to Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Kerberos Policy.

If the value for "Maximum lifetime for user ticket" is 0 or greater than 10 hours, this is a finding.'
  desc 'fix', %q(Configure the policy value in the Default Domain Policy for Computer Configuration ->  Policies -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy -> "Maximum lifetime for user ticket" to a maximum of 10 hours, but not 0 which equates to "Ticket doesn't expire".)
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27769r475524_chk'
  tag severity: 'medium'
  tag gid: 'V-226067'
  tag rid: 'SV-226067r569184_rule'
  tag stig_id: 'WN12-AC-000012-DC'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27757r475525_fix'
  tag 'documentable'
  tag legacy: ['SV-51164', 'V-2378']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
