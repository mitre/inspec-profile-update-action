control 'SV-213984' do
  title 'SQL Server must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75% of maximum audit record storage capacity.'
  desc 'Organizations are required to use a central log management system, so, under normal conditions, the audit space allocated to SQL Server on its own server will not be an issue. However, space will still be required on the server for SQL Server audit records in transit, and, under abnormal conditions, this could fill up. Since a requirement exists to halt processing upon audit failure, a service outage would result. 
 
If support personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion.  
 
The appropriate support staff include, at a minimum, the ISSO and the DBA/SA. 
 
Monitoring of free space can be accomplished using Microsoft System Center or a third-party monitoring tool.'
  desc 'check', 'The operating system and SQL Server offer a number of methods for checking the drive or volume free space. Locate the destination drive where SQL Audits are stored and review system configuration.  
 
If no alert exist to notify support staff in the event the SQL Audit drive reaches 75%, this is a finding.'
  desc 'fix', 'Utilize operating system alerting mechanisms, SQL Agent, Operations Management tools, and/or third-party tools to configure the system to notify appropriate support staff immediately upon storage volume utilization reaching 75%.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15201r313735_chk'
  tag severity: 'medium'
  tag gid: 'V-213984'
  tag rid: 'SV-213984r754629_rule'
  tag stig_id: 'SQL6-D0-011000'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag fix_id: 'F-15199r313736_fix'
  tag 'documentable'
  tag legacy: ['SV-93935', 'V-79229']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
