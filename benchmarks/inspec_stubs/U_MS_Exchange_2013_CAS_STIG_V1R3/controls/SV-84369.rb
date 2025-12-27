control 'SV-84369' do
  title 'Exchange must have Audit data on separate partitions.'
  desc 'Log files help establish a history of activities, and can be useful in detecting attack attempts or determining tuning adjustments to improve availability. Audit log content must always be considered sensitive, and in need of protection. 

Successful exploit of an application server vulnerability may well be logged by monitoring or audit processes when it occurs. By writing log and audit data to a separate partition where separate security contexts protect them, it may offer the ability to protect this information from being modified or removed by the exploit mechanism.'
  desc 'check', "Review the Email Domain Security Plan (EDSP).

Determine the audit logs' assigned partition.

Note: By default, the logs are located on the application partition in \\Program Files\\Microsoft\\Exchange Server\\V15\\Logging.

If the log files are not on a separate partition from the application, this is a finding."
  desc 'fix', 'Update the EDSP.

Configure the audit log location to be on a partition drive separate from the application.'
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-70191r1_chk'
  tag severity: 'low'
  tag gid: 'V-69747'
  tag rid: 'SV-84369r1_rule'
  tag stig_id: 'EX13-CA-000085'
  tag gtitle: 'SRG-APP-000125'
  tag fix_id: 'F-75953r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
