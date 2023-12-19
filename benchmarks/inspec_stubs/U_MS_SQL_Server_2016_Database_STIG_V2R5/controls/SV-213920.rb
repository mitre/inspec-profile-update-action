control 'SV-213920' do
  title 'SQL Server must associate organization-defined types of security labels having organization-defined security label values with information in transmission.'
  desc 'Without the association of security labels to information, there is no basis for SQL Server to make security-related access-control decisions.

Security labels are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information. These labels are typically associated with internal data structures (e.g., tables, rows) within the database and are used to enable the implementation of access control and flow control policies; reflect special dissemination, handling, or distribution instructions; or support other aspects of the information security policy. One example includes marking data as classified or FOUO. These security labels may be assigned manually or during data processing, but, either way, it is imperative these assignments are maintained while the data is in storage. If the security labels are lost when the data is stored, there is the risk of a data compromise.

The mechanism used to support security labeling may be a feature of SQL Server, a third-party product, or custom application code.'
  desc 'check', 'If security labeling is not required, this is not a finding.

If security labeling requirements have been specified, but neither a third-party solution nor a SQL Server Row-Level security solution is implemented that reliably maintains labels on information in transmission, this is a finding.'
  desc 'fix', 'Deploy SQL Server Row-Level Security (see link below) or a third-party software, or add custom data structures, data elements and application code, to provide reliable security labeling of information in transmission.

https://msdn.microsoft.com/en-us/library/dn765131.aspx'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Database'
  tag check_id: 'C-15138r313192_chk'
  tag severity: 'medium'
  tag gid: 'V-213920'
  tag rid: 'SV-213920r855955_rule'
  tag stig_id: 'SQL6-D0-002700'
  tag gtitle: 'SRG-APP-000314-DB-000310'
  tag fix_id: 'F-15136r313193_fix'
  tag 'documentable'
  tag legacy: ['SV-93809', 'V-79103']
  tag cci: ['CCI-002264']
  tag nist: ['AC-16 a']
end
