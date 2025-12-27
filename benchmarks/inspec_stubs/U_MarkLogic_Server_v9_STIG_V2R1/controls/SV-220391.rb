control 'SV-220391' do
  title 'MarkLogic Server must generate audit records when unsuccessful attempts to access security objects occur.'
  desc 'Changes to the security configuration must be tracked.

This requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', 'Review MarkLogic configuration to determine if audit records will be produced when security objects are accessed, to include reads, creations, modifications and deletions of data, and execution of logic.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Verify audit enabled field is set to true. If the setting is not true, this is a finding. 
5. Under the Audit Restrictions - Outcome section, verify the security-access event for auditing is set to "both". If the setting is not "both", this is a finding.'
  desc 'fix', 'Configure MarkLogic to produce audit records when security objects are accessed, to include reads, creations, modifications and deletions of data, and execution of logic.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Set the audit enabled field to true.
5. Enable the security-access event for auditing.
6. Under the Audit Restrictions section, enable "both" under the Outcome selection.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22106r401624_chk'
  tag severity: 'medium'
  tag gid: 'V-220391'
  tag rid: 'SV-220391r622777_rule'
  tag stig_id: 'ML09-00-009400'
  tag gtitle: 'SRG-APP-000492-DB-000333'
  tag fix_id: 'F-22095r401625_fix'
  tag 'documentable'
  tag legacy: ['SV-110131', 'V-101027']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
