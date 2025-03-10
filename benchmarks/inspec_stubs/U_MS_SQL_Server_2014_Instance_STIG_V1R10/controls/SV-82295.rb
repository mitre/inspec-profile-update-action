control 'SV-82295' do
  title 'SQL Server and the operating system must protect SQL Server audit features from unauthorized removal.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

This focuses on external tools for log maintenance and review.  Other STIG requirements govern SQL Server privileges to maintain trace or audit definitions.'
  desc 'check', 'In Windows, review the access permissions to tools used to view or modify audit log data (to include traces used for audit purposes).

If appropriate permissions and access controls to prevent unauthorized deletions are not applied to these tools, this is a finding.'
  desc 'fix', 'Apply or modify Windows permissions on tools used to view or modify audit log data (to include traces used for audit purposes), to make them accessible by authorized personnel only.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68373r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67805'
  tag rid: 'SV-82295r1_rule'
  tag stig_id: 'SQL4-00-014100'
  tag gtitle: 'SRG-APP-000123-DB-000204'
  tag fix_id: 'F-73921r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
end
