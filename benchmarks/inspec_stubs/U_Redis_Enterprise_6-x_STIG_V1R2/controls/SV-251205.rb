control 'SV-251205' do
  title 'Redis Enterprise DBMS must protect its audit features from unauthorized access.'
  desc 'Redis Enterprise does not come with unique tools to view log data and logging is not configurable. Logs are stored in a standard log file on the host operating system that is accessible using standard Linux tooling. Only users in the admin role can view or modify privileged settings in the Redis Enterprise UI.

Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. 

Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. It is, therefore, imperative that access to audit tools be controlled and protected from unauthorized access. 

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, OS-provided audit tools, vendor-provided audit tools, and open-source audit tools needed to successfully view and manipulate audit information system activity and records. 

If an attacker were to gain access to audit tools, they could analyze audit logs for system weaknesses or weaknesses in the auditing itself. An attacker could also manipulate logs to hide evidence of malicious activity.'
  desc 'check', 'For validating privilege on the OS, verify user ownership, group ownership, and permissions on the Redis audit directory.

From Linux command line as root:
> ls - ald /var/opt/redislabs/log/ (or whatever the organizationally defined location for Redis logs)

If the User owner is not a defined admin, this is a finding.

If the Group owner is not a defined admin group, this is a finding.

If the directory is more permissive than 700, this is a finding.

For validating privileges on the control plane, verify Redis Admin users listed on the control plane against documented approved admin users. If any users have unauthorized admin privileges, this is a finding.'
  desc 'fix', 'Apply or modify access controls and permissions (in the file system/operating system) to tools used to view or modify audit log data. Tools must be accessible by authorized personnel only.

/var/opt/redislabs/log/ (or whatever the organizationally defined location for Redis logs) should have an appropriate and documented admin user and group owner, and the directory should not have permissions more than 700. 

To update these permissions, run the following commands:
chown redislabs:redislabs /var/opt/redislabs/log
chmod 700 /var/opt/redislabs/log'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54640r804803_chk'
  tag severity: 'medium'
  tag gid: 'V-251205'
  tag rid: 'SV-251205r804805_rule'
  tag stig_id: 'RD6X-00-006700'
  tag gtitle: 'SRG-APP-000121-DB-000202'
  tag fix_id: 'F-54594r804804_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
