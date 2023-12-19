control 'SV-36170' do
  title 'Kerberos user logon restrictions must be enforced.'
  desc 'This policy setting determines whether the Kerberos Key Distribution Center (KDC) validates every request for a session ticket against the user rights policy of the target computer. The policy is enabled by default which is the most secure setting for validating access to target resources is not circumvented.'
  desc 'check', 'Verify the following is configured in the Default Domain Policy.

Open "Group Policy Management".
Navigate to "Group Policy Objects" in the Domain being reviewed (Forest >> Domains >> Domain). 
Right click on the "Default Domain Policy", select "Edit".
Navigate to Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy.

If the policy "Enforce user logon restrictions" is not set to "Enabled", this is a finding.'
  desc 'fix', 'Configure the policy value in the Default Domain Policy for Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy >> "Enforce user logon restrictions" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-71079r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2376'
  tag rid: 'SV-36170r2_rule'
  tag stig_id: 'AD.4029_2008_R2'
  tag gtitle: 'Kerberos-User Logon Restrictions'
  tag fix_id: 'F-76923r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
