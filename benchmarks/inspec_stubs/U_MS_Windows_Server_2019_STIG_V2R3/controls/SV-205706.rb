control 'SV-205706' do
  title 'Windows Server 2019 computer clock synchronization tolerance must be limited to five minutes or less.'
  desc "This setting determines the maximum time difference (in minutes) that Kerberos will tolerate between the time on a client's clock and the time on a server's clock while still considering the two clocks synchronous. In order to prevent replay attacks, Kerberos uses timestamps as part of its protocol definition. For timestamps to work properly, the clocks of the client and the server need to be in sync as much as possible.

"
  desc 'check', 'This applies to domain controllers. It is NA for other systems.

Verify the following is configured in the Default Domain Policy:

Open "Group Policy Management".

Navigate to "Group Policy Objects" in the Domain being reviewed (Forest >> Domains >> Domain).
 
Right-click on the "Default Domain Policy".

Select "Edit".

Navigate to Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy.

If the "Maximum tolerance for computer clock synchronization" is greater than "5" minutes, this is a finding.'
  desc 'fix', 'Configure the policy value in the Default Domain Policy for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy >> "Maximum tolerance for computer clock synchronization" to a maximum of "5" minutes or less.'
  impact 0.5
  ref 'DPMS Target Windows Server 2019'
  tag check_id: 'C-5971r355036_chk'
  tag severity: 'medium'
  tag gid: 'V-205706'
  tag rid: 'SV-205706r569188_rule'
  tag stig_id: 'WN19-DC-000060'
  tag gtitle: 'SRG-OS-000112-GPOS-00057'
  tag fix_id: 'F-5971r355037_fix'
  tag satisfies: ['SRG-OS-000112-GPOS-00057', 'SRG-OS-000113-GPOS-00058']
  tag 'documentable'
  tag legacy: ['V-93451', 'SV-103537']
  tag cci: ['CCI-001941', 'CCI-001942']
  tag nist: ['IA-2 (8)', 'IA-2 (9)']
end
