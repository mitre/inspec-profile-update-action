control 'SV-221215' do
  title 'Exchange audit data must be on separate partitions.'
  desc 'Log files help establish a history of activities and can be useful in detecting attack attempts or determining tuning adjustments to improve availability. Audit log content must always be considered sensitive and in need of protection.   

Successful exploit of an application server vulnerability may well be logged by monitoring or audit processes when it occurs. Writing log and audit data to a separate partition where separate security contexts protect them may offer the ability to protect this information from being modified or removed by the exploit mechanism.'
  desc 'check', "Review the Email Domain Security Plan (EDSP).

Determine the audit logs' assigned partition.

Note: By default, the logs are located on the application partition in \\Program Files\\Microsoft\\Exchange Server\\V15\\Logging\\.   

If the log files are not on a separate partition from the application, this is a finding."
  desc 'fix', 'Update the EDSP.

Configure the audit log location to be on a partition drive separate from the application.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22930r411771_chk'
  tag severity: 'medium'
  tag gid: 'V-221215'
  tag rid: 'SV-221215r612603_rule'
  tag stig_id: 'EX16-ED-000140'
  tag gtitle: 'SRG-APP-000125'
  tag fix_id: 'F-22919r411772_fix'
  tag 'documentable'
  tag legacy: ['SV-95221', 'V-80511']
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
