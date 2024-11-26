control 'SV-226068' do
  title 'The Kerberos policy user ticket renewal maximum lifetime must be limited to 7 days or less.'
  desc "This setting determines the period of time (in days) during which a user's TGT may be renewed.  This security configuration limits the amount of time an attacker has to crack the TGT and gain access."
  desc 'check', 'Verify the following is configured in the Default Domain Policy.

Open "Group Policy Management".
Navigate to "Group Policy Objects" in the Domain being reviewed (Forest > Domains > Domain). 
Right click on the "Default Domain Policy".
Select Edit.
Navigate to Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Kerberos Policy.

If the "Maximum lifetime for user ticket renewal" is greater than 7 days, this is a finding.'
  desc 'fix', 'Configure the policy value in the Default Domain Policy for Computer Configuration ->  Policies -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy -> "Maximum lifetime for user ticket renewal" to a maximum of 7 days or less.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27770r475527_chk'
  tag severity: 'medium'
  tag gid: 'V-226068'
  tag rid: 'SV-226068r569184_rule'
  tag stig_id: 'WN12-AC-000013-DC'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27758r475528_fix'
  tag 'documentable'
  tag legacy: ['SV-51166', 'V-2379']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
