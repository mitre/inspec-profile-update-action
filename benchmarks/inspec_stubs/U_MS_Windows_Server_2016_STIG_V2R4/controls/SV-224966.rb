control 'SV-224966' do
  title 'The Kerberos service ticket maximum lifetime must be limited to 600 minutes or less.'
  desc 'This setting determines the maximum amount of time (in minutes) that a granted session ticket can be used to access a particular service. Session tickets are used only to authenticate new connections with servers. Ongoing operations are not interrupted if the session ticket used to authenticate the connection expires during the connection.

'
  desc 'check', 'This applies to domain controllers. It is NA for other systems.

Verify the following is configured in the Default Domain Policy.

Open "Group Policy Management".

Navigate to "Group Policy Objects" in the Domain being reviewed (Forest >> Domains >> Domain). 

Right-click on the "Default Domain Policy".

Select "Edit".

Navigate to Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy.

If the value for "Maximum lifetime for service ticket" is "0" or greater than "600" minutes, this is a finding.'
  desc 'fix', %q(Configure the policy value in the Default Domain Policy for Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy >> "Maximum lifetime for service ticket" to a maximum of "600" minutes, but not "0", which equates to "Ticket doesn't expire".)
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26657r465800_chk'
  tag severity: 'medium'
  tag gid: 'V-224966'
  tag rid: 'SV-224966r569186_rule'
  tag stig_id: 'WN16-DC-000030'
  tag gtitle: 'SRG-OS-000112-GPOS-00057'
  tag fix_id: 'F-26645r465801_fix'
  tag satisfies: ['SRG-OS-000112-GPOS-00057', 'SRG-OS-000113-GPOS-00058']
  tag 'documentable'
  tag legacy: ['SV-88013', 'V-73361']
  tag cci: ['CCI-001941', 'CCI-001942']
  tag nist: ['IA-2 (8)', 'IA-2 (9)']
end
