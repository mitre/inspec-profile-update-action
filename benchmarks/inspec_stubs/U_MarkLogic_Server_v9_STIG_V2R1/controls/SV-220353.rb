control 'SV-220353' do
  title 'MarkLogic Server must protect its audit configuration from unauthorized modification.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys to make access decisions regarding the modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Review access permissions to tools used to view or modify audit log data. Since MarkLogic Audit logs are stored in plain text files, this includes text editors provided by the OS.

Alternatively, Encryption-at-Rest can be enabled for the logs. This would ensure only individuals/systems with a valid encryption key may access the data within logs and audit files.

If appropriate permissions and access controls are not applied to prevent unauthorized modification of these tools, and Encryption-at-Rest is not enabled for logs, this is a finding.

Perform the check from the MarkLogic Admin Interface with a user that holds administrative-level privileges.
1. Click the Clusters icon on the left tree menu.
2. Click the Keystore tab.
3. If "logs encryption" is set to "off", this is a finding.'
  desc 'fix', 'Add or modify access controls and permissions to tools used to view or modify audit log data, including OS text editors. Since MarkLogic Audit logs are stored in plain text files, this includes text editors provided by the OS. Tools must be accessible by authorized personnel only.

Alternatively, Encryption-at-Rest for system logs may be enabled to prevent unauthorized disclosure of contained information. 

Perform the fix from the MarkLogic Admin Interface with a user that holds administrative-level privileges.
1. Click the Clusters icon on the left tree menu.
2. Click the Keystore tab.
3. Change "logs encryption" setting to "on".'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22068r401510_chk'
  tag severity: 'medium'
  tag gid: 'V-220353'
  tag rid: 'SV-220353r622777_rule'
  tag stig_id: 'ML09-00-002300'
  tag gtitle: 'SRG-APP-000122-DB-000203'
  tag fix_id: 'F-22057r401511_fix'
  tag 'documentable'
  tag legacy: ['SV-110053', 'V-100949']
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
