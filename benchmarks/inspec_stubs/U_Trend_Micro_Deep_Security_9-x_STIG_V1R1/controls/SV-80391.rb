control 'SV-80391' do
  title 'Trend Deep Security must use cryptographic mechanisms to protect the integrity of audit information.'
  desc 'Audit records may be tampered with; if the integrity of audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

Protection of audit records and audit data is of critical importance. Cryptographic mechanisms are the industry established standard used to protect the integrity of audit data. An example of a cryptographic mechanism is the computation and application of a cryptographic-signed hash using asymmetric cryptography. 

This requirement applies to applications that generate or process audit records.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure cryptographic mechanisms are used to protect the integrity of audit information.

Verify PDF encryption is enabled for report generation.
Go to Administration >> User Management >> Users >> Right-click an administrative user account and select "Properties".
Within the "Settings" tab select "Enable PDF Encryption".

If "Enable PDF Encryption" is not enabled, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to use cryptographic mechanisms to protect the integrity of audit information.

Enabled encryption for report generation.
Go to Administration >> User Management >> Users >> Right-click an administrative user account and select "Properties".
Within the "Settings" tab select "Enable PDF Encryption" and enter a password.'
  impact 0.7
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66549r1_chk'
  tag severity: 'high'
  tag gid: 'V-65901'
  tag rid: 'SV-80391r1_rule'
  tag stig_id: 'TMDS-00-000125'
  tag gtitle: 'SRG-APP-000126'
  tag fix_id: 'F-71977r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001350']
  tag nist: ['AU-9 (3)']
end
