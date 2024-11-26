control 'SV-24645' do
  title 'Procedures and restrictions for import of production data to development databases should be documented, implemented and followed.'
  desc 'Data export from production databases may include sensitive data. Application developers may not be cleared for or have need-to-know to sensitive data. Any access they may have to production data would be considered unauthorized access and subject the sensitive data to unlawful or unauthorized disclosure.'
  desc 'check', 'If the database being reviewed is not a production database or does not contain sensitive data, this check is Not a Finding.
 
Review documented policy, procedures and proof of implementation for restrictions placed on data exports from the production database.

Policy and procedures should include that only authorized users have access to DBMS export utilities and that export data is properly sanitized prior to import to a development database.

Policy and procedures may also include that developers be granted the necessary clearance and need-to-know prior to import of production data.

If documented policy, procedures and proof of implementation are not present or complete, this is a Finding.

If methods to sanitize sensitive data are required and not documented or followed, this is a Finding.'
  desc 'fix', 'Develop, document and implement policy and procedures that provide restrictions for production data export.

Require users and administrators assigned privileges that allow the export of production data from a production database to acknowledge understanding of export restrictions.

Restrict permissions allowing use or access to database export procedures or functions to authorized users.

Ensure sensitive data from production is sanitized prior to import to a development database (See check DG0076).

Grant access and need-to-know to developers where allowed by policy.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29169r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15140'
  tag rid: 'SV-24645r1_rule'
  tag stig_id: 'DG0069-ORACLE11'
  tag gtitle: 'Production data import to development DBMS'
  tag fix_id: 'F-26181r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
