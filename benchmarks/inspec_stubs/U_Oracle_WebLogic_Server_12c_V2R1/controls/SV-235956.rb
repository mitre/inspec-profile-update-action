control 'SV-235956' do
  title 'Oracle WebLogic must protect audit information from any type of unauthorized read access.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

Application servers contain admin interfaces that allow reading and manipulation of audit records. Therefore, these interfaces should not allow for unfettered access to those records. Application servers also write audit data to log files which are stored on the OS, so appropriate file permissions must also be used to restrict access.

Audit information includes all information (e.g., audit records, audit settings, transaction logs, and audit reports) needed to successfully audit information system activity. Application servers must protect audit information from unauthorized read access.'
  desc 'check', "1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Users and Groups' tab -> 'Users' tab
5. From 'Users' table, select a user that must not have audit read access
6. From users settings page, select 'Groups' tab
7. Ensure the 'Chosen' table does not contain any of the following roles - 'Admin', 'Deployer', 'Monitor', 'Operator'
8. Repeat steps 5-7 for all users that must not have audit read access

If any users that should not have access to read audit information contain any of the roles of 'Admin', 'Deployer', 'Monitor' or 'Operator', this is a finding."
  desc 'fix', "1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Users and Groups' tab -> 'Users' tab
5. From 'Users' table, select a user that must not have audit read access
6. From users settings page, select 'Groups' tab
7. From the 'Chosen' table, use the shuttle buttons to remove all of the following roles - 'Admin', 'Deployer', 'Monitor', 'Operator'
8. Click 'Save'
9. Repeat steps 5-8 for all users that must not have audit read access"
  impact 0.3
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39175r628644_chk'
  tag severity: 'low'
  tag gid: 'V-235956'
  tag rid: 'SV-235956r628646_rule'
  tag stig_id: 'WBLC-02-000095'
  tag gtitle: 'SRG-APP-000118-AS-000078'
  tag fix_id: 'F-39138r628645_fix'
  tag 'documentable'
  tag legacy: ['SV-70515', 'V-56261']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
