control 'SV-91647' do
  title 'The DBN-6300 must uniquely identify and authenticate organizational administrators (or processes acting on behalf of organizational administrators).'
  desc 'To ensure accountability and prevent unauthenticated access, organizational administrators must be uniquely identified and authenticated for all network management accesses to prevent potential misuse and compromise of the system.'
  desc 'check', 'Verify that there is one local account configured on the DBN-6300.

Navigate to Settings >> User Management.

Verify that there is one account on the system and that this account has unrestricted privileges.

If no local account is configured in this way, or more than one account is configured locally, this is a finding.'
  desc 'fix', 'Verify that there is one local account configured on the DBN-6300.

Navigate to Settings >> User Management.

Verify that there is one account on the system, and that this account has unrestricted privileges.

If there is more than one local account, delete the additional accounts by clicking on the trashcan icon on the far right of the account(s) in question, until all accounts are deleted except for one administrative account with unlimited privileges.

If there is no local account with administrative or unlimited privileges, create one using the following steps: 

Navigate to Settings >> User Management >> Users.

Click on the New User button.

Enter a username for Username, a name (optional), a 15-character (minimum) complex password, and the role of either Admin or Unrestricted.

After all entries are filled, click "Save".'
  impact 0.7
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76575r2_chk'
  tag severity: 'high'
  tag gid: 'V-76951'
  tag rid: 'SV-91647r1_rule'
  tag stig_id: 'DBNW-DM-000049'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-83647r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']
end
