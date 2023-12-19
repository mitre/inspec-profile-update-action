control 'SV-28505' do
  title 'The computer clock synchronization tolerance must be limited to 5 minutes or less.'
  desc "This setting determines the maximum time difference (in minutes) that Kerberos will tolerate between the time on a client's clock and the time on a server's clock while still considering the two clocks synchronous.  In order to prevent replay attacks, Kerberos uses timestamps as part of its protocol definition. For timestamps to work properly, the clocks of the client and the server need to be in sync as much as possible."
  desc 'check', 'Verify the following is configured in the Default Domain Policy.

Open "Group Policy Management".
Navigate to "Group Policy Objects" in the Domain being reviewed (Forest >> Domains >> Domain). 
Right click on the "Default Domain Policy", select "Edit".
Navigate to Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy.

If the "Maximum tolerance for computer clock synchronization" is greater than "5" minutes, this is a finding.'
  desc 'fix', 'Configure the policy value in the Default Domain Policy for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy >> "Maximum tolerance for computer clock synchronization" to "5" minutes or less.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-71097r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2380'
  tag rid: 'SV-28505r2_rule'
  tag stig_id: 'AD.4033_2008'
  tag gtitle: 'Kerberos - Computer Clock Sync'
  tag fix_id: 'F-76941r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001941', 'CCI-001942']
  tag nist: ['IA-2 (8)', 'IA-2 (9)']
end
