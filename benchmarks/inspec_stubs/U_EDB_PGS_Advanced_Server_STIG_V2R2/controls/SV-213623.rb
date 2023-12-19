control 'SV-213623' do
  title 'The EDB Postgres Advanced Server must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75% of maximum audit record storage capacity.'
  desc 'Organizations are required to use a central log management system, so under normal conditions, the audit space allocated to the DBMS on its own server will not be an issue. However, space will still be required on the DBMS server for audit records in transit, and, under abnormal conditions, this could fill up. Since a requirement exists to halt processing upon audit failure, a service outage would result.

If support personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion. 

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.'
  desc 'check', 'If Postgres Enterprise Manager (PEM) or another similar monitoring capability is not installed and configured to probe storage volume utilization of "<postgresql data directory>" and notify appropriate support staff upon storage volume utilization reaching 75 percent, this is a finding.

(The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)'
  desc 'fix', 'Install PEM and configure a probe to monitor "<postgresql data directory>" and notify appropriate support staff upon storage volume utilization reaching 75 percent.

(The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)

Example steps for creating a probe are below, using the thin client (browser) PEM interface. Refer also to the Supplemental Procedures document, supplied with this STIG.

Open the PEM web console in a browser

 - Log in
 - Click on the agent for the machine to be monitored
   - Select "Management | Probe Configuration"
   - Select "Disk Space" and set the check interval as you like
   - Select "Management | Alerting"
   - Name the definition "Audit Log Full"
   - Select Template "Disk Consumption Percentage"
   - Set Frequency, Comparison Operator, and Thresholds (1 minute, >, 
95/96/97 for example)
   - Enter the Mount Point for where the audit log is
   - Click Notification tab
   - Click Email all alerts
   - Click "Execute Script" on Monitored Server
   - Enter script to showdown postgres, generally "service ppas-95 stop"
   - Click Add/Change to save, click "OK" to exit dialog box'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14845r290181_chk'
  tag severity: 'medium'
  tag gid: 'V-213623'
  tag rid: 'SV-213623r508024_rule'
  tag stig_id: 'PPS9-00-008000'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag fix_id: 'F-14843r290182_fix'
  tag 'documentable'
  tag legacy: ['SV-83603', 'V-68999']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
