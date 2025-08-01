control 'SV-220373' do
  title 'Access to MarkLogic Server files must be limited to relevant processes and to authorized, administrative users.'
  desc 'Applications, including DBMSs, must prevent unauthorized and unintended information transfer via shared system resources. Permitting only DBMS processes and authorized, administrative users to have access to the files where the database resides helps ensure those files are not shared inappropriately and are not open to backdoor access and manipulation.

Encryption at rest protects data on media, that is, data at rest as opposed to data moving across a communications channel, otherwise known as data in motion. Increasing security risks and compliance requirements sometimes mandate the use of encryption at rest to prevent unauthorized access to data on disk.

Encryption at rest can be configured to encrypt data, log files, and configuration files separately. Encryption is only applied to newly created files once encryption at rest is enabled, and does not apply to existing files without further action by the user. For existing data, a merge or re-index will trigger encryption of data, a configuration change will trigger encryption of configuration files, and log rotation will initiate log encryption.

For more information:
See: https://docs.marklogic.com/guide/security/encryption'
  desc 'check', 'If the application owner and Authorizing Official have determined that encryption of data at rest is NOT required, this is not a finding.

If full-disk encryption is being used, this is not a finding.

Review system documentation to determine whether the system handles classified information. If the system does not handle classified information, the severity of this check should be downgraded to Category II.

Review MarkLogic settings to determine whether controls exist to protect the confidentiality and integrity of data at rest in the database.

From a command line at the OS level, verify User ownership, Group ownership, and permissions on the files:
> ls -al /var/opt/MarkLogic/

If the User owner is not "daemon", and encryption at rest is not enabled, this is a finding.

If the Group owner is not "daemon", and encryption at rest is not enabled, this is a finding.

If the directory is more permissive than 750, and encryption at rest is not enabled, this is a finding.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Databases icon.
2. Click the database to be checked.
3. If the "data encryption" drop-down is set to ON, this is not a finding, and no further checks need to be performed.
4. If the "data encryption" drop-down is set to OFF, continue the check.
5. If the "data encryption" drop-down is set to default-cluster, continue the check with the steps below:
a. Click the Clusters icon.
b. Click [Cluster Name].
c. Click the Configure Tab.
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
3. Select ON from the data encryption drop-down.

OR

Change owner and group of /var/opt/MarkLogic to user daemon from the command line with a privileged user:
> chown -R daemon.daemon /var/opt/MarkLogic

Change permissions of /var/opt/MarkLogic to 750 (rwx by owner only) from the command line
> chmod 750 /var/opt/MarkLogic'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22088r401570_chk'
  tag severity: 'medium'
  tag gid: 'V-220373'
  tag rid: 'SV-220373r622777_rule'
  tag stig_id: 'ML09-00-005500'
  tag gtitle: 'SRG-APP-000243-DB-000374'
  tag fix_id: 'F-22077r401571_fix'
  tag 'documentable'
  tag legacy: ['SV-110095', 'V-100991']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
