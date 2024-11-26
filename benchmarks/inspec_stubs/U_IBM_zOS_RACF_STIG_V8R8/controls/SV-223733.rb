control 'SV-223733' do
  title 'IBM z/OS SMF recording options for the FTP Server must be configured to write SMF records for all eligible events.'
  desc 'The FTP Server can provide audit data in the form of SMF records. The SMF data produced by the FTP Server provides transaction information for both successful and unsuccessful FTP commands. Failure to collect and retain audit data may contribute to the loss of accountability and hamper security audit activities.

'
  desc 'check', 'If FTPDATA is configured with the following SMF statements, this is not a finding.

FTP.DATA Configuration Statements
SMF TYPE119
SMFJES TYPE119
SMFSQL TYPE119
SMFAPPE [Not coded or commented out]
SMFDEL [Not coded or commented out]
SMFEXIT [Not coded or commented out]
SMFLOGN [Not coded or commented out]
SMFREN [Not coded or commented out]
SMFRETR [Not coded or commented out]
SMFSTOR [Not coded or commented out]'
  desc 'fix', 'Configure SMF options to conform to the specifications in the FTPDATA Configuration Statements below:

SMF TYPE119
SMFJES TYPE119
SMFSQL TYPE119
SMFAPPE [Not coded or commented out]
SMFDEL [Not coded or commented out]
SMFEXIT [Not coded or commented out]
SMFLOGN [Not coded or commented out]
SMFREN [Not coded or commented out]
SMFRETR [Not coded or commented out]
SMFSTOR [Not coded or commented out]

The FTP Server can provide audit data in the form of SMF records. SMF record type 119, the TCP/IP Statistics record, can be written with the following subtypes:

70 – Append
70 – Delete and Multiple Delete
72 – Invalid Logon Attempt
70 – Rename
70 – Get (Retrieve) and Multiple Get
70 – Put (Store and Store Unique) and Multiple Put

SMF data produced by the FTP Server provides transaction information for both successful and unsuccessful FTP commands. This data may provide valuable information for security audit activities. Type 119 records use a more standard format and provide more information.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25406r514887_chk'
  tag severity: 'medium'
  tag gid: 'V-223733'
  tag rid: 'SV-223733r853606_rule'
  tag stig_id: 'RACF-FT-000010'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-25394r514888_fix'
  tag satisfies: ['SRG-OS-000032-GPOS-00013', 'SRG-OS-000392-GPOS-00172']
  tag 'documentable'
  tag legacy: ['V-98173', 'SV-107277']
  tag cci: ['CCI-000067', 'CCI-002884']
  tag nist: ['AC-17 (1)', 'MA-4 (1) (a)']
end
