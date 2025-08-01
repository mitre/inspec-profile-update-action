control 'SV-239214' do
  title 'Rsyslog must be configured to monitor VMware Postgres logs.'
  desc 'Organizations are required to use a central log management system, so, under normal conditions, the audit space allocated to the DBMS on its own server will not be an issue. However, space will still be required on the DBMS server for audit records in transit, and, under abnormal conditions, this could fill up. Because a requirement exists to halt processing upon audit failure, a service outage would result.

If support personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion. 

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.

'
  desc 'check', 'At the command prompt, execute the following command:

# cat /etc/vmware-syslog/stig-services-vpostgres.conf

Expected result:

input(type="imfile"
File="/var/log/vmware/vpostgres/serverlog.std*"
Tag="vpostgres-first"
Severity="info"
Facility="local0")

input(type="imfile"
File="/var/log/vmware/vpostgres/postgresql-*.log"
Tag="vpostgres"
Severity="info"
Facility="local0")

If the file does not exist, this is a finding.

If the output of the command does not match the expected result above, this is a finding.

If there is no output from the command, vPostgres will default to "stderr", and this is not a finding.'
  desc 'fix', 'Navigate to and open /etc/vmware-syslog/stig-services-vpostgres.conf.

Create the file if it does not exist.

Set the contents of the file as follows:

input(type="imfile"
File="/var/log/vmware/vpostgres/serverlog.std*"
Tag="vpostgres-first"
Severity="info"
Facility="local0")

input(type="imfile"
File="/var/log/vmware/vpostgres/postgresql-*.log"
Tag="vpostgres"
Severity="info"
Facility="local0")'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 PostgreSQL'
  tag check_id: 'C-42447r679013_chk'
  tag severity: 'medium'
  tag gid: 'V-239214'
  tag rid: 'SV-239214r679015_rule'
  tag stig_id: 'VCPG-67-000022'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag fix_id: 'F-42406r679014_fix'
  tag satisfies: ['SRG-APP-000359-DB-000319', 'SRG-APP-000360-DB-000320', 'SRG-APP-000092-DB-000208']
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
