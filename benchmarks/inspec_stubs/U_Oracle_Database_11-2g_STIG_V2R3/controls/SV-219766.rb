control 'SV-219766' do
  title 'The DBMS must protect audit tools from unauthorized deletion.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. 

Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. 

It is, therefore, imperative that access to audit tools be controlled and protected from unauthorized access.  

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, OS-provided audit tools, vendor-provided audit tools, and open source audit tools needed to successfully view and manipulate audit information system activity and records. 

If an attacker were to gain access to audit tools, he could analyze audit logs for system weaknesses or weaknesses in the auditing itself.  An attacker could also manipulate logs to hide evidence of malicious activity.'
  desc 'check', 'Review access permissions to tools used to view or modify audit log data. These tools may include the DBMS itself or tools external to the database. If appropriate permissions and access controls are not applied to prevent unauthorized deletion of these tools, this is a finding.'
  desc 'fix', 'Add or modify access controls and permissions to tools used to view or modify audit log data. Only authorized personnel must be able to delete these tools.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21491r307147_chk'
  tag severity: 'medium'
  tag gid: 'V-219766'
  tag rid: 'SV-219766r395835_rule'
  tag stig_id: 'O112-C2-009800'
  tag gtitle: 'SRG-APP-000123-DB-000204'
  tag fix_id: 'F-21490r307148_fix'
  tag 'documentable'
  tag legacy: ['SV-66417', 'V-52201']
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
end
