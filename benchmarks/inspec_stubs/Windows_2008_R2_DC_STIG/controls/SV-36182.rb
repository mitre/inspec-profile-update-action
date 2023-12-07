control 'SV-36182' do
  title 'The Kerberos user ticket renewal maximum lifetime must be limited to 7 days or less.'
  desc "This setting determines the period of time (in days) during which a user's Ticket Granting Ticket (TGT) may be renewed. This security configuration limits the amount of time an attacker has to crack the TGT and gain access."
  desc 'check', 'Verify the following is configured in the Default Domain Policy.

Open "Group Policy Management".
Navigate to "Group Policy Objects" in the Domain being reviewed (Forest >> Domains >> Domain). 
Right click on the "Default Domain Policy", select "Edit".
Navigate to Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy.

If the "Maximum lifetime for user ticket renewal" is greater than "7" days, this is a finding.'
  desc 'fix', 'Configure the policy value in the Default Domain Policy for Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy >> "Maximum lifetime for user ticket renewal" to "7" days or less.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-71085r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2379'
  tag rid: 'SV-36182r2_rule'
  tag stig_id: 'AD.4032_2008_R2'
  tag gtitle: 'Kerberos-User Ticket Renewal'
  tag fix_id: 'F-76929r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
