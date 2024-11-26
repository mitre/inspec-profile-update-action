control 'SV-252173' do
  title 'MongoDB must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75 percent of maximum audit record storage capacity.'
  desc 'Organizations are required to use a central log management system; so, under normal conditions, the audit space allocated to MongoDB on its own server will not be an issue. However, space will still be required on MongoDB server for audit records in transit, and, under abnormal conditions, this could fill up. Since a requirement exists to halt processing upon audit failure, a service outage would result.

If support personnel are not notified immediately upon storage volume utilization reaching 75 percent, they are unable to plan for storage capacity expansion.

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.'
  desc 'check', 'Verify that auditing is enabled in the mongodb configuration file (default location: /etc/mongod.conf) and view the auditlog.path to identify the storage volume.

This is only applicable where the auditLog.destination is set to file.

Verify that MongoDB Ops Manager or other organization approved monitoring software is installed.

Verify that the required alert in the monitoring software to send an alert where storage volume holding the auditLog file utilization reaches 75 percent.

If appropriate support staff are not notified immediately upon storage volume utilization reaching 75 percent, this is a finding.'
  desc 'fix', 'View the %MongoDB configuration file% (default location: /etc/mongod.conf) and view the auditlog.path to identify the storage volume.

Install MongoDB Ops Manager or other organization-approved monitoring software.

Configure the required alert in the monitoring software to send an alert where storage volume holding the auditLog file utilization reaches 75 percent.'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55629r813899_chk'
  tag severity: 'medium'
  tag gid: 'V-252173'
  tag rid: 'SV-252173r813901_rule'
  tag stig_id: 'MD4X-00-005000'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag fix_id: 'F-55579r813900_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
