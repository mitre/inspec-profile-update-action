control 'SV-207280' do
  title 'Exchange must protect audit data against unauthorized access.'
  desc 'Log files help establish a history of activities and can be useful in detecting attack attempts or determining tuning adjustments to improve availability. Audit log content must always be considered sensitive and in need of protection. Audit data available for modification by a malicious user can be altered to conceal malicious activity. Audit data might also provide a means for the malicious user to plan unauthorized activities that exploit weaknesses.
  
The contents of audit logs are protected against unauthorized access, modification, or deletion. Only authorized auditors and the audit functions should be granted Read and Write access to audit log data.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP). 

Determine the authorized groups or users that should have access to the audit data.

If any group or user has modify privileges for the audit data that is not documented in the EDSP, this is a finding.'
  desc 'fix', "Update the EDSP.

Restrict any unauthorized groups' or users' modify permissions for the audit logs.

By default, the logs are located on the application partition in \\Program Files\\Microsoft\\Exchange Server\\V15\\Logging"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7538r393353_chk'
  tag severity: 'medium'
  tag gid: 'V-207280'
  tag rid: 'SV-207280r811169_rule'
  tag stig_id: 'EX13-MB-000070'
  tag gtitle: 'SRG-APP-000119'
  tag fix_id: 'F-7538r811168_fix'
  tag 'documentable'
  tag legacy: ['SV-84589', 'V-69967']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
