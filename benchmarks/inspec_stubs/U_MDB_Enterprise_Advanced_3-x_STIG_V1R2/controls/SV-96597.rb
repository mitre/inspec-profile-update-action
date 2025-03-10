control 'SV-96597' do
  title 'MongoDB must protect the confidentiality and integrity of all information at rest.'
  desc 'This control is intended to address the confidentiality and integrity of information at rest in non-mobile devices and covers user information and system information. Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive, tape drive) within an organizational information system. Applications and application users generate information throughout the course of their application use.

User data generated, as well as application-specific configuration data, needs to be protected. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate.

If the confidentiality and integrity of application data is not protected, the data will be open to compromise and unauthorized modification.'
  desc 'check', 'If the MongoDB Encrypted Storage Engines is being used, ensure that the "security.enableEncryption" option is set to "true" in the MongoDB configuration file (default location: /etc/mongod.conf) or that MongoDB was started with the "--enableEncryption" command line option.

Check the MongoDB configuration file (default location: /etc/mongod.conf).

If the following parameter is not present, this is a finding.

security:
enableEncryption: "true"

If any mongod process is started with "--enableEncryption false", this is a finding.'
  desc 'fix', 'Ensure that the MongoDB Configuration file (default location: /etc/mongod.conf) has the following set:

security:
enableEncryption: "true"

Ensure that any mongod process that contains the option "--enableEcryption" has "true" as its parameter <boolean> value (e.g., "--enableEncryption true").

Stop/start (restart) and mongod process using either the MongoDB configuration file or that contains the "--enableEncryption" option.'
  impact 0.5
  ref 'DPMS Target MongoDB 3.x'
  tag check_id: 'C-81675r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81883'
  tag rid: 'SV-96597r1_rule'
  tag stig_id: 'MD3X-00-000440'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-88733r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
