control 'SV-213721' do
  title 'DB2 must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75% of maximum audit record storage capacity.'
  desc 'Organizations are required to use a central log management system, so, under normal conditions, the audit space allocated to the DBMS on its own server will not be an issue. However, space will still be required on the DBMS server for audit records in transit, and, under abnormal conditions, this could fill up. Since a requirement exists to halt processing upon audit failure, a service outage would result.

If support personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion. 

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.'
  desc 'check', 'Use the following command to find the directory for the Audit Data Path: 

     $db2audit describe 

If there is no monitoring of the Audit Data Path location at the Operating System level using OS utilities or system management utilities to send an alert at 75% space utilization, this is a finding.'
  desc 'fix', 'Use the Operating system tools or external utilities to monitor the Audit Data Path and set alerts for 75% space utilization.'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14942r295212_chk'
  tag severity: 'medium'
  tag gid: 'V-213721'
  tag rid: 'SV-213721r879732_rule'
  tag stig_id: 'DB2X-00-007600'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag fix_id: 'F-14940r295213_fix'
  tag 'documentable'
  tag legacy: ['SV-89245', 'V-74571']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
