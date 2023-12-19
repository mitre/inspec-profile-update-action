control 'SV-220372' do
  title 'MarkLogic Server must protect the confidentiality and integrity of all information at rest.'
  desc 'This control is intended to address the confidentiality and integrity of information at rest in non-mobile devices and covers user information and system information. Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive, tape drive) within an organizational information system. Applications and application users generate information throughout the course of their application use. 

User data generated, as well as application-specific configuration data, needs to be protected. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate. 

If the confidentiality and integrity of application data is not protected, the data will be open to compromise and unauthorized modification.

Encryption at rest protects data on media, that is, data at rest as opposed to data moving across a communications channel (data in motion). Increasing security risks and compliance requirements sometimes mandate the use of encryption at rest to prevent unauthorized access to data on disk.

Encryption at rest can be configured to encrypt data, log files, and configuration files separately. Encryption is only applied to newly created files once encryption at rest is enabled, and does not apply to existing files without further action by the user. For existing data, a merge or re-index will trigger encryption of data, a configuration change will trigger encryption of configuration files, and log rotation will initiate log encryption.

More information can be found here:
https://docs.marklogic.com/guide/security/encryption'
  desc 'check', 'If the application owner and Authorizing Official have determined that encryption of data at rest is NOT required, this is not a finding.

If full-disk encryption is being used, this is not a finding. 

Review system documentation to determine whether the system handles classified information. If the system does not handle classified information, the severity of this check should be downgraded to Category II.

Review MarkLogic settings to determine whether controls exist to protect the confidentiality and integrity of data at rest in the database.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Databases icon.
2. Click the database to be checked.
3. If the "data encryption" drop-down is set to ON, this is not a finding, and no further checks need to be performed.
4. If the "data encryption" drop-down is set to OFF, continue the check.
5. If the "data encryption" drop-down is set to default-cluster, continue the check with the steps below:
a. Click the Clusters icon.
b. Click [Cluster Name].
c. Click the Keystore Tab.
d. If the Cluster Default Encryption configuration is OFF, this is a finding.

Findings Matrix
-------------------------------------------------------
Database Cfg. | Cluster Cfg | Finding
--------------------------------------------------------
ON | *Any* | No
*Any* | Force | No
Default-cluster | Default-on | No
Default-cluster | Default-off | Yes
Off | Default-on | Yes
Off | Default-off | Yes'
  desc 'fix', 'Apply appropriate controls to protect the confidentiality and integrity of data at rest in the database.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Databases icon.
2. Click the database to be fixed.
3. Select ON from the data encryption drop-down.'
  impact 0.7
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22087r401567_chk'
  tag severity: 'high'
  tag gid: 'V-220372'
  tag rid: 'SV-220372r622777_rule'
  tag stig_id: 'ML09-00-005100'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-22076r401568_fix'
  tag 'documentable'
  tag legacy: ['SV-110093', 'V-100989']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
