control 'SV-213824' do
  title 'SQL Server and/or the operating system must protect its audit configuration from unauthorized modification.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

This focuses on external tools for log maintenance and review.  Other STIG requirements govern SQL Server privileges to maintain trace or audit definitions.'
  desc 'check', 'In Windows, review the access permissions to tools used to view or modify audit log data (to include traces used for audit purposes).

If appropriate permissions and access controls to prevent unauthorized changes are not applied to these tools, this is a finding.'
  desc 'fix', 'Apply or modify Windows permissions on tools used to view or modify audit log data (to include traces used for audit purposes), to make them accessible by authorized personnel only.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15043r312823_chk'
  tag severity: 'medium'
  tag gid: 'V-213824'
  tag rid: 'SV-213824r395832_rule'
  tag stig_id: 'SQL4-00-014000'
  tag gtitle: 'SRG-APP-000122-DB-000203'
  tag fix_id: 'F-15041r312824_fix'
  tag 'documentable'
  tag legacy: ['SV-82293', 'V-67803']
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
