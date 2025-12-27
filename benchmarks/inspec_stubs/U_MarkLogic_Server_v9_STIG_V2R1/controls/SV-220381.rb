control 'SV-220381' do
  title 'MarkLogic Server must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75 percent of maximum audit record storage capacity.'
  desc 'Organizations are required to use a central log management system, so, under normal conditions, the audit space allocated to the DBMS on its own server will not be an issue. However, space will still be required on the DBMS server for audit records in transit, and, under abnormal conditions, this could fill up. Since a requirement exists to halt processing upon audit failure, a service outage would result.

If support personnel are not notified immediately upon storage volume utilization reaching 75 percent, they are unable to plan for storage capacity expansion. 

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.'
  desc 'check', 'Review system configuration to determine if appropriate support staff are not notified immediately upon storage volume utilization reaching 75 percent.

If the Organization is not using Ops Director, or a third-party tool for storage volume utilization/alerting, this is a finding.'
  desc 'fix', 'Configure the system to notify appropriate support staff immediately upon storage volume utilization reaching 75 percent.

Use MarkLogic Ops Director with Alerts, or third-party tool to monitor storage Volume utilization/alerting.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22096r401594_chk'
  tag severity: 'medium'
  tag gid: 'V-220381'
  tag rid: 'SV-220381r855486_rule'
  tag stig_id: 'ML09-00-007300'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag fix_id: 'F-22085r401595_fix'
  tag 'documentable'
  tag legacy: ['SV-110111', 'V-101007']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
