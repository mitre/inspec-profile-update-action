control 'SV-222507' do
  title 'The application must use cryptographic mechanisms to protect the integrity of audit information.'
  desc 'Audit records may be tampered with; if the integrity of audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

Protection of audit records and audit data is of critical importance. Cryptographic mechanisms are the industry established standard used to protect the integrity of audit data. An example of a cryptographic mechanism is the computation and application of a cryptographic-signed hash using asymmetric cryptography.

This requirement applies to applications that generate, process or manage audit records and is applied once audit processing has completed and the audit record is being stored.'
  desc 'check', 'Review the system documentation and interview the application administrator for details regarding application architecture, audit methods, and provided audit tools.

Identify the location of the application audit information.

If the application is configured to utilize a centralized audit log solution that uses cryptographic methods that meet this requirement such as creating cryptographic hash values or message digests that can be used to validate integrity of audit files, the requirement is not applicable.

Ask application administrator to demonstrate the cryptographic mechanisms used to protect the integrity of audit data.

Verify when application logs are stored on the file system, a process that includes the creation of an integrity check of the audit file being stored is utilized. This integrity check can be the creation of a checksum, message digest or other one-way cryptographic hash of the audit file that is created.

If an integrity check is not created to protect the integrity of the audit information, this is a finding.'
  desc 'fix', 'Configure the application to create an integrity check consisting of a cryptographic hash or one-way digest that can be used to establish the integrity when storing log files.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24177r493429_chk'
  tag severity: 'medium'
  tag gid: 'V-222507'
  tag rid: 'SV-222507r508029_rule'
  tag stig_id: 'APSC-DV-001350'
  tag gtitle: 'SRG-APP-000126'
  tag fix_id: 'F-24166r493430_fix'
  tag 'documentable'
  tag legacy: ['SV-84119', 'V-69497']
  tag cci: ['CCI-001350']
  tag nist: ['AU-9 (3)']
end
