control 'SV-239200' do
  title 'VMware Postgres database must protect log files from unauthorized access and modification.'
  desc 'If audit data were to become compromised, competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.

This requirement can be achieved through multiple methods, which will depend on system architecture and design. Some commonly employed methods include ensuring log files have the proper file system permissions, using file system protections, and limiting log data location. 

Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring that audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

'
  desc 'check', "At the command prompt, enter the following command:

# find /var/log/vmware/vpostgres/* -xdev -type f -a '(' -not -perm 600 -o -not -user vpostgres -o -not -group users ')' -exec ls -ld {} \\;

If any files are returned, this is a finding."
  desc 'fix', %q(At the command prompt, enter the following command:

# chmod 600 <file>
# chown vpostgres:users <file>

Note: Replace <file> with the file with incorrect permissions.

At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_file_mode TO '0600';"

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 PostgreSQL'
  tag check_id: 'C-42433r678971_chk'
  tag severity: 'medium'
  tag gid: 'V-239200'
  tag rid: 'SV-239200r678973_rule'
  tag stig_id: 'VCPG-67-000005'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag fix_id: 'F-42392r678972_fix'
  tag satisfies: ['SRG-APP-000118-DB-000059', 'SRG-APP-000119-DB-000060', 'SRG-APP-000120-DB-000061']
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
