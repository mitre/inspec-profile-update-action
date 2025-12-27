control 'SV-254389' do
  title 'Windows Server 2022 Kerberos policy user ticket renewal maximum lifetime must be limited to seven days or less.'
  desc "This setting determines the period of time (in days) during which a user's Ticket Granting Ticket (TGT) may be renewed. This security configuration limits the amount of time an attacker has to crack the TGT and gain access.

"
  desc 'check', 'This applies to domain controllers. It is NA for other systems.

Verify the following is configured in the Default Domain Policy:

Open "Group Policy Management".

Navigate to "Group Policy Objects" in the Domain being reviewed (Forest >> Domains >> Domain).
 
Right-click on the "Default Domain Policy".

Select "Edit".

Navigate to Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy.

If the "Maximum lifetime for user ticket renewal" is greater than "7" days, this is a finding.'
  desc 'fix', 'Configure the policy value in the Default Domain Policy for Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy >> Maximum lifetime for user ticket renewal to a maximum of "7" days or less.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57874r848981_chk'
  tag severity: 'medium'
  tag gid: 'V-254389'
  tag rid: 'SV-254389r848983_rule'
  tag stig_id: 'WN22-DC-000050'
  tag gtitle: 'SRG-OS-000112-GPOS-00057'
  tag fix_id: 'F-57825r848982_fix'
  tag satisfies: ['SRG-OS-000112-GPOS-00057', 'SRG-OS-000113-GPOS-00058']
  tag 'documentable'
  tag cci: ['CCI-001941', 'CCI-001942']
  tag nist: ['IA-2 (8)', 'IA-2 (9)']
end
