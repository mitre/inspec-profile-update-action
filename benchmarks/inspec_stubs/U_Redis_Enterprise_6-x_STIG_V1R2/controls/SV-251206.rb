control 'SV-251206' do
  title 'Redis Enterprise DBMS must protect its audit configuration from unauthorized modification.'
  desc 'Redis Enterprise does not come with unique tools to view log data and logging is not configurable. Logs are stored in a standard log file on the host operating system that is accessible using standard Linux tooling. Only users in the admin role can view or modify privileged settings in the Redis Enterprise UI.

Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'For validating privilege on the OS, verify user ownership, group ownership, and permissions on the redis audit directory. 

From Linux command line as root:
> ls - ald /var/opt/redislabs/log/ (or whatever the organizationally defined location for Redis logs)

If the User owner is not a defined admin, this is a finding. 

If the Group owner is not a defined admin group, this is a finding.

If the directory is more permissive than 700, this is a finding.

For validating privileges on the control plane, verify Redis Admin users that are listed on the control plane against documented approved admin users. If any users have unauthorized admin privileges, this is a finding.'
  desc 'fix', 'Apply or modify access controls and permissions (in the file system/operating system) to tools used to view or modify audit log data. Tools must be accessible by authorized personnel only.

/var/opt/redislabs/log/ (or whatever the organizationally defined location for Redis logs) should have an appropriate and documented admin user and group owner and the directory should not have permissions more than 700. 

To update these permissions, run the following commands:
chown redislabs:redislabs /var/opt/redislabs/log
chmod 700 /var/opt/redislabs/log'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54641r804806_chk'
  tag severity: 'medium'
  tag gid: 'V-251206'
  tag rid: 'SV-251206r804808_rule'
  tag stig_id: 'RD6X-00-006800'
  tag gtitle: 'SRG-APP-000122-DB-000203'
  tag fix_id: 'F-54595r804807_fix'
  tag 'documentable'
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
