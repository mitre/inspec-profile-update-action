control 'SV-239214' do
  title 'Rsyslog must be configured to monitor VMware Postgres logs.'
  desc 'For performance reasons, rsyslog file monitoring is preferred over configuring VMware Postgres to send events to a syslog facility. Without ensuring that logs are created, that rsyslog configs are created, and that those configs are loaded, the log file monitoring and shipping will not be effective.

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
  tag rid: 'SV-239214r879732_rule'
  tag stig_id: 'VCPG-67-000022'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag fix_id: 'F-42406r679014_fix'
  tag satisfies: ['SRG-APP-000359-DB-000319', 'SRG-APP-000360-DB-000320', 'SRG-APP-000092-DB-000208']
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
