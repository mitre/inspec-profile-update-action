control 'SV-251614' do
  title 'Passwords sent through ODBC/JDBC must be encrypted.'
  desc 'Unencrypted passwords transmitted from ODBC and JDBC may be intercepted to prevent their being intercepted in a plain-text format.'
  desc 'check', 'When using ODBC (with the CCI communications protocol) or a JDBC type 2 driver, if SSL encryption is not being used with CAICCI r2.1 and above, this is a finding.

When using ODBC (with the IDMS communications protocol), if SSL encryption is not being used as indicated on the "Server" tab of the Data Source definition, this is a finding.

When using a JDBC type 4 driver, if SSL is not being used as indicated by the connection URL, this is a finding.'
  desc 'fix', 'If using ODBC (with the CCI communications protocol) or a JDBC type 2 driver, SSL encryption can be enabled using CAICCI r2.1 and above. Select the SSL option in the CAICCI properties panel and configure and start the CCISSL task on the mainframe. 

If using ODBC (with the IDMS communications protocol), SSL encryption can be enabled by selecting the "SSL" check-box on the "Server" tab of the Data Source definition, and providing the certificate name(s) on the "SSL" tab within the CA IDMS ODBC Administrator.

If using a JDBC type 4 driver, SSL encryption can be enabled by using the SSL parameter on the JDBC connection URL. Setup is described in informational APAR QI83006 on CA Support Online.'
  impact 0.3
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55049r807707_chk'
  tag severity: 'low'
  tag gid: 'V-251614'
  tag rid: 'SV-251614r807709_rule'
  tag stig_id: 'IDMS-DB-000340'
  tag gtitle: 'SRG-APP-000172-DB-000075'
  tag fix_id: 'F-55003r807708_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
