control 'SV-256842' do
  title 'Compliance Guardian must provide automated mechanisms for supporting account management functions.'
  desc 'Remote access (e.g., Remote Desktop Protocol [RDP]) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include dial-up, broadband, and wireless. 

'
  desc 'check', 'Compliance Guardian supports integration with Active Directory (AD) for automated account management.

Check the Compliance Guardian configuration to ensure AD Integration is enabled.
- Log on to Compliance Guardian with admin account.
- On the Control Panel page in the General Security section, click "Authentication Manager".
- Navigate to "AD Integration".
- Verify that the "AD Integration" option is enabled.

If the AD Integration option is not enabled, this is a finding.'
  desc 'fix', 'Configure the Compliance Guardian configuration to ensure AD Integration is enabled.
- Log on to Compliance Guardian with admin account.
- On the Control Panel page in the Authentication Manager section, click "Authentication Manager".
- Navigate to "AD Integration".
- Set the Action of "AD Integration" to "Enable".
- Save settings.

Add AD user or group to Compliance Guardian by Account Manager; realize automated mechanisms through AD account management functions.'
  impact 0.5
  ref 'DPMS Target AvePoint Compliance Guardian'
  tag check_id: 'C-60517r890134_chk'
  tag severity: 'medium'
  tag gid: 'V-256842'
  tag rid: 'SV-256842r890136_rule'
  tag stig_id: 'APCG-00-000015'
  tag gtitle: 'SRG-APP-000023'
  tag fix_id: 'F-60460r890135_fix'
  tag satisfies: ['SRG-APP-000023', 'SRG-APP-000025', 'SRG-APP-000065', 'SRG-APP-000163', 'SRG-APP-000164', 'SRG-APP-000165', 'SRG-APP-000166', 'SRG-APP-000167', 'SRG-APP-000168', 'SRG-APP-000169', 'SRG-APP-000170', 'SRG-APP-000171', 'SRG-APP-000173', 'SRG-APP-000174', 'SRG-APP-000190', 'SRG-APP-000234', 'SRG-APP-000291', 'SRG-APP-000292', 'SRG-APP-000293', 'SRG-APP-000294', 'SRG-APP-000295', 'SRG-APP-000318', 'SRG-APP-000319', 'SRG-APP-000320', 'SRG-APP-000345', 'SRG-APP-000397', 'SRG-APP-000401', 'SRG-APP-000503', 'SRG-APP-000505', 'SRG-APP-000506', 'SRG-APP-000509']
  tag 'documentable'
  tag cci: ['CCI-000015', 'CCI-000017', 'CCI-000044', 'CCI-000172', 'CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-000195', 'CCI-000196', 'CCI-000198', 'CCI-000199', 'CCI-000200', 'CCI-000205', 'CCI-000795', 'CCI-001133', 'CCI-001619', 'CCI-001682', 'CCI-001683', 'CCI-001684', 'CCI-001685', 'CCI-001686', 'CCI-001991', 'CCI-002041', 'CCI-002130', 'CCI-002132', 'CCI-002145', 'CCI-002238', 'CCI-002361']
  tag nist: ['AC-2 (1)', 'AC-2 (3) (d)', 'AC-7 a', 'AU-12 c', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (b)', 'IA-5 (1) (c)', 'IA-5 (1) (d)', 'IA-5 (1) (d)', 'IA-5 (1) (e)', 'IA-5 (1) (a)', 'IA-4 e', 'SC-10', 'IA-5 (1) (a)', 'AC-2 (2)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'IA-5 (2) (d)', 'IA-5 (1) (f)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (11)', 'AC-7 b', 'AC-12']
end
