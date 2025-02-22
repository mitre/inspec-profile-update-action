control 'SV-235162' do
  title 'The MySQL Database Server 8.0 must protect its audit features from unauthorized removal.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', "Check users with permissions to administer MySQL Auditing.

select * from information_schema.user_privileges where privilege_type = 'AUDIT_ADMIN';

If unauthorized accounts have these the AUDIT_ADMIN privilege, this is a finding."
  desc 'fix', 'This requirement is a permanent finding and cannot be fixed. An appropriate mitigation for the system must be implemented, but this finding cannot be considered fixed.'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38381r623606_chk'
  tag severity: 'medium'
  tag gid: 'V-235162'
  tag rid: 'SV-235162r879581_rule'
  tag stig_id: 'MYS8-00-008200'
  tag gtitle: 'SRG-APP-000123-DB-000204'
  tag fix_id: 'F-38344r623607_fix'
  tag 'documentable'
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
end
