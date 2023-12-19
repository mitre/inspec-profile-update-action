control 'SV-44038' do
  title 'Audit data must be on separate partitions.'
  desc 'Log files help establish a history of activities, and can be useful in detecting attack attempts or determining tuning adjustments to improve availability.   Audit log content must always be considered sensitive, and in need of protection.   

Successful exploit of an application server vulnerability may well be logged by monitoring or audit processes when it occurs.  By writing log and audit data to a separate partition where separate security contexts protect them, it may offer the ability to protect this information from being modified or removed by the exploit mechanism.'
  desc 'check', "Obtain the Email Domain Security Plan (EDSP) and locate the audit logs assigned partition.

By default the logs are located on the application partition in '\\Program Files\\Microsoft\\Exchange Server\\V14\\Logging\\'.   

If the log files are not on a separate partition from the application, this is a finding."
  desc 'fix', 'Configure the audit log location to be on a partition drive separate from the application.  

Document the location in the EDSP.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41725r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33618'
  tag rid: 'SV-44038r1_rule'
  tag stig_id: 'Exch-2-839'
  tag gtitle: 'Exch-2-839'
  tag fix_id: 'F-37510r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
