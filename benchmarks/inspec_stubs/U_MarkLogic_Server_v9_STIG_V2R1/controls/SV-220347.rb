control 'SV-220347' do
  title 'MarkLogic Server must initiate session auditing upon startup.'
  desc "Session auditing is used when a user's activities are under investigation. To ensure all activity is captured during the periods when session auditing is in use, it must be in operation for the entire time the DBMS is running."
  desc 'check', 'Check that MarkLogic session-level auditing and specific session audits are currently defined and session auditing is enabled; or if a third-party product is available for session auditing.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to check resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Inspect the audit enabled field, a value of false means there is no auditing, this is a finding.'
  desc 'fix', 'Configure MarkLogic session-level auditing, ensure specific session audits are currently defined, and enable session auditing or verify a third-party product is available for session auditing.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to check resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Set the audit enabled field to true.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22062r401492_chk'
  tag severity: 'medium'
  tag gid: 'V-220347'
  tag rid: 'SV-220347r622777_rule'
  tag stig_id: 'ML09-00-000800'
  tag gtitle: 'SRG-APP-000092-DB-000208'
  tag fix_id: 'F-22051r401493_fix'
  tag 'documentable'
  tag legacy: ['SV-110041', 'V-100937']
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
