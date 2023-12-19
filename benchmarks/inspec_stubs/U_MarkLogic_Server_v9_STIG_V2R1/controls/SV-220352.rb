control 'SV-220352' do
  title 'MarkLogic Server must protect its audit features from unauthorized access.'
  desc '<0> [object Object]'
  desc 'check', 'Review access permissions to tools used to view or modify audit log data. Since MarkLogic Audit logs are stored in plain text files, this includes text editors provided by the OS.

Alternatively, enable Encryption-at-Rest for the logs. This would ensure only individuals/systems with a valid encryption key may access the data within logs and audit files.

If appropriate permissions and access controls are not applied to prevent unauthorized modification of these tools, and Encryption-at-Rest is not enabled for logs, this is a finding.

Perform the check from the MarkLogic Admin Interface with a user that holds administrative-level privileges.
1. Click the Clusters icon on the left tree menu.
2. Click the Keystore tab.
3. If "logs encryption" is set to "off", this is a finding.'
  desc 'fix', 'Add or modify access controls and permissions for tools used to view or modify audit log data, including OS text editors. Since MarkLogic Audit logs are stored in plain text files, this includes text editors provided by the OS. Tools must be accessible by authorized personnel only.

Alternatively, Encryption-at-Rest for system logs may be enabled to prevent unauthorized disclosure of contained information. 

Perform the fix from the MarkLogic Admin Interface with a user that holds administrative-level privileges.
1. Click the Clusters icon on the left tree menu.
2. Click the Keystore tab.
3. Change "logs encryption" setting to "on".'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22067r401507_chk'
  tag severity: 'medium'
  tag gid: 'V-220352'
  tag rid: 'SV-220352r622777_rule'
  tag stig_id: 'ML09-00-002200'
  tag gtitle: 'SRG-APP-000121-DB-000202'
  tag fix_id: 'F-22056r401508_fix'
  tag legacy: ['SV-110051', 'V-100947']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
