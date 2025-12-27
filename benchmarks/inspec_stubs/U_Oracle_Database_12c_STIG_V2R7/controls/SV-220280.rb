control 'SV-220280' do
  title 'The system must protect audit tools from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data.

Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. It is, therefore, imperative that access to audit tools be controlled and protected from unauthorized access.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, OS-provided audit tools, vendor-provided audit tools, and open source audit tools needed to successfully view and manipulate audit information system activity and records.

If an attacker were to gain access to audit tools, he could analyze audit logs for system weaknesses or weaknesses in the auditing itself.  An attacker could also manipulate logs to hide evidence of malicious activity.'
  desc 'check', 'Review access permissions to tools used to view or modify audit log data. These tools may include the DBMS itself or tools external to the database.

If appropriate permissions and access controls to prevent unauthorized access are not applied to these tools, this is a finding.'
  desc 'fix', 'Add or modify access controls and permissions to tools used to view or modify audit log data. Tools must be accessible by authorized personnel only.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21995r391971_chk'
  tag severity: 'medium'
  tag gid: 'V-220280'
  tag rid: 'SV-220280r879579_rule'
  tag stig_id: 'O121-C2-009600'
  tag gtitle: 'SRG-APP-000121-DB-000202'
  tag fix_id: 'F-21987r391972_fix'
  tag 'documentable'
  tag legacy: ['SV-76149', 'V-61659']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
