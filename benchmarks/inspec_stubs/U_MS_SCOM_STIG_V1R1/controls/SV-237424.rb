control 'SV-237424' do
  title 'Manually configured SCOM Run As accounts must be set to More Secure distribution.'
  desc 'The Microsoft SCOM privileged Run As accounts are used to execute work flow tasks on target endpoints. A SCOM Run As account creates an interactive log on session to perform its tasks. The interactive session could allow an attacker to harvest and reuse these credentials. The SCOM less-secure distribution option configures a Run As account to run on every SCOM agent within the environment, making it easier for an attacker to compromise a critical account. 

The use of the SCOM "More Secure" option restricts Run As accounts to specific systems. This restricts a compromised account to a specific set of systems limiting the ability of an attacker to move laterally within the network. A less secure distribution means that if any server running a SCOM agent is compromised, then the accounts credentials may be reused by an attacker.'
  desc 'check', 'Review the account distribution settings on the SCOM Management server.

Open the Operations Console and select the Administration workspace.

Under Run As Configuration, select Accounts.

Double-click on each account listed under the Windows type and select the distribution tab (note that the network system and local system accounts do not need to be checked).

If any Run As account is set to the "less secure" distribution option, this is a finding.'
  desc 'fix', 'Open the Operations Console and select the Administration workspace.

Under Run As Configuration, select Accounts.

Double-click on the account(s) in question. Click the Distribution tab. Click the "More Secure" radio button and then click the "Add" button next to the green plus sign. In the filter by section, type the computer name(s) for each computer that is required to use the Run As account and click "Search". Double-click on the account in the available users section to add it to the selected users section. Click OK when finished.

Note: If the Run As account in question is not assigned to any run-as profile, it is recommended that the Run As account be deleted.'
  impact 0.7
  ref 'DPMS Target Microsoft SCOM'
  tag check_id: 'C-40643r643916_chk'
  tag severity: 'high'
  tag gid: 'V-237424'
  tag rid: 'SV-237424r643918_rule'
  tag stig_id: 'SCOM-AC-000002'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag fix_id: 'F-40606r643917_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
