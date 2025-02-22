control 'SV-220281' do
  title 'The system must protect audit tools from unauthorized modification.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data.

Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data.

If the tools are compromised it could provide attackers with the capability to manipulate log data. It is, therefore, imperative that audit tools be controlled and protected from unauthorized modification.

Audit tools include, but are not limited to, OS provided audit tools, vendor provided audit tools, and open source audit tools needed to successfully view and manipulate audit information system activity and records.

If an attacker were to gain access to audit tools he could analyze audit logs for system weaknesses or weaknesses in the auditing itself. An attacker could also manipulate logs to hide evidence of malicious activity.'
  desc 'check', 'Review access permissions to tools used to view or modify audit log data. These tools may include the DBMS itself or tools external to the database.

If appropriate permissions and access controls are not applied to prevent unauthorized modification of these tools, this is a finding.'
  desc 'fix', 'Add or modify access controls and permissions to tools used to view or modify audit log data. Tools must be modifiable by authorized personnel only.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21996r391974_chk'
  tag severity: 'medium'
  tag gid: 'V-220281'
  tag rid: 'SV-220281r395832_rule'
  tag stig_id: 'O121-C2-009700'
  tag gtitle: 'SRG-APP-000122-DB-000203'
  tag fix_id: 'F-21988r391975_fix'
  tag 'documentable'
  tag legacy: ['SV-76151', 'V-61661']
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
