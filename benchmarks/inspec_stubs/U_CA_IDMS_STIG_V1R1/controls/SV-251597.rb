control 'SV-251597' do
  title 'IDMS must protect against the use of web-based applications that use generic IDs.'
  desc 'Web-based applications that allow a generic ID can be a door into IDMS allowing unauthorized changes whose authors may not be determined.'
  desc 'check', 'If there are web-based applications to which individual users sign on, and a generic ID associated with the application is used to access back-end IDMS databases, this is a finding.'
  desc 'fix', 'For web-based applications using generic IDs, set the individual user ID (external identity) to be recorded in the journal.

For JDBC applications, use the "IdmsConnection setIdentity" method.

For ODBC applications, use the "SQLSetConnectAttr" function with the IDMS_ATTR_EXTERNAL_IDENTITY attribute type.

Run journal report "JREPORT 010" and" JREPORT 008" to audit the individual user ID.'
  impact 0.3
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55032r807656_chk'
  tag severity: 'low'
  tag gid: 'V-251597'
  tag rid: 'SV-251597r808349_rule'
  tag stig_id: 'IDMS-DB-000170'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-54986r807657_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
