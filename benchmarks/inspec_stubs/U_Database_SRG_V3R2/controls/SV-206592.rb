control 'SV-206592' do
  title 'The DBMS must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75% of maximum audit record storage capacity.'
  desc 'Organizations are required to use a central log management system, so, under normal conditions, the audit space allocated to the DBMS on its own server will not be an issue. However, space will still be required on the DBMS server for audit records in transit, and, under abnormal conditions, this could fill up. Since a requirement exists to halt processing upon audit failure, a service outage would result.

If support personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion. 

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.'
  desc 'check', 'Review system configuration.

If appropriate support staff are not notified immediately upon storage volume utilization reaching 75%, this is a finding.'
  desc 'fix', 'Configure the system to notify appropriate support staff immediately upon storage volume utilization reaching 75%.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6852r291444_chk'
  tag severity: 'medium'
  tag gid: 'V-206592'
  tag rid: 'SV-206592r617447_rule'
  tag stig_id: 'SRG-APP-000359-DB-000319'
  tag gtitle: 'SRG-APP-000359'
  tag fix_id: 'F-6852r291445_fix'
  tag 'documentable'
  tag legacy: ['SV-72487', 'V-58057']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
