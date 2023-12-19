control 'SV-252165' do
  title 'MongoDB must protect the confidentiality and integrity of all information at rest.'
  desc 'This control is intended to address the confidentiality and integrity of information at rest in non-mobile devices and covers user information and system information. Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive, tape drive) within an organizational information system. Applications and application users generate information throughout the course of their application use.

User data generated, as well as application-specific configuration data, needs to be protected. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate.

If the confidentiality and integrity of application data is not protected, the data will be open to compromise and unauthorized modification.'
  desc 'check', 'To provide integrity and confidentiality for data at rest, MongoDB must be configured to use the Encrypted Storage Engine.

Run the following command to verify whether or not the Encrypted Storage Engine is enabled:

 db.serverStatus().encryptionAtRest.encryptionEnabled

Any output other than true is a finding.

Next, validate whether the Encrypted Storage Engine is running with an AEAD block cipher, which provides integrity, by running the following command:

 db.serverStatus().encryptionAtRest.encryptionCipherMode

Any response other than AES256-GCM is a finding.

Finally, validate that the system is configured to use KMIP to obtain a master encryption key, rather than storing the master key on the local filesystem. 

Run: 

 db.serverStatus().encryptionAtRest.encryptionKeyId

If the response is local or no response, this is a finding.'
  desc 'fix', 'Enable the Encrypted Storage Engine with KMIP as the key storage mechanism and AES256-GCM as the encryption mode. 

Consult MongoDB documentation for encryption setup instruction here:

https://docs.mongodb.com/v4.4/tutorial/configure-encryption/'
  impact 0.7
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55621r813875_chk'
  tag severity: 'high'
  tag gid: 'V-252165'
  tag rid: 'SV-252165r863329_rule'
  tag stig_id: 'MD4X-00-003800'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-55571r813876_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
