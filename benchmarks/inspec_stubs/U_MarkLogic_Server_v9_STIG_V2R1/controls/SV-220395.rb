control 'SV-220395' do
  title 'MarkLogic Server must generate audit records when unsuccessful attempts to add privileges/permissions occur.'
  desc 'Failed attempts to change the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized attempts to elevate or restrict privileges could go undetected. 

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', 'Review MarkLogic security and audit configurations to verify audit records are produced when the DBMS denies the addition of privileges/permissions/role membership or when other errors prevent the addition of privileges/permissions/role membership.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Inspect the audit enabled field, a value of false means auditing is not enabled, this is a finding. 
5. If audit enabled field is true but the user-role-addition event is not selected, this is a finding.
6. Under the Audit Restrictions - Outcome section, verify the security-access event for auditing is set to "both". If the setting is not "both", this is a finding.'
  desc 'fix', 'Configure MarkLogic to produce audit records when it denies attempts to add privileges/permissions/role membership or when other errors prevent attempts to add privileges/permissions/role membership.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Set the audit enabled field to true.
5. Enable the user-role-addition event for auditing.
6. Enable "both" for the audit restriction under the outcome selection.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22110r401636_chk'
  tag severity: 'medium'
  tag gid: 'V-220395'
  tag rid: 'SV-220395r622777_rule'
  tag stig_id: 'ML09-00-009800'
  tag gtitle: 'SRG-APP-000495-DB-000327'
  tag fix_id: 'F-22099r401637_fix'
  tag 'documentable'
  tag legacy: ['SV-110139', 'V-101035']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
