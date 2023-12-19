control 'SV-213869' do
  title 'SQL Server, the operating system, or the storage system must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75% of maximum audit record storage capacity.'
  desc "Organizations are required to use a central log management system, so, under normal conditions, the audit space allocated to SQL Server on its own server will not be an issue. However, space will still be required on the DBMS server for audit records in transit, and, under abnormal conditions, this could fill up. Since a requirement exists to halt processing upon audit failure, a service outage would result.

As noted elsewhere in this document, SQL Server's Audit and/or Trace features can be used for auditing purposes.  This requirement applies to both.

If support personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion. 

The monitoring and alerting may be done at the database level, the operating system level, or by specialized monitoring tools. 

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA."
  desc 'check', 'Review system configuration.

If appropriate support staff are not notified immediately upon storage volume utilization reaching 75%, this is a finding.'
  desc 'fix', 'Configure the system to notify appropriate support staff immediately upon storage volume utilization reaching 75%.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15088r312958_chk'
  tag severity: 'medium'
  tag gid: 'V-213869'
  tag rid: 'SV-213869r855540_rule'
  tag stig_id: 'SQL4-00-033400'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag fix_id: 'F-15086r312959_fix'
  tag 'documentable'
  tag legacy: ['SV-82383', 'V-67893']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
