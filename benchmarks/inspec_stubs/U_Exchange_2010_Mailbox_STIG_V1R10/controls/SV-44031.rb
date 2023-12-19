control 'SV-44031' do
  title 'Audit data must be protected against unauthorized access.'
  desc 'Log files help establish a history of activities, and can be useful in detecting attack attempts or determining tuning adjustments to improve availability.   Audit log content must always be considered sensitive, and in need of protection.  Audit data available for modification by a malicious user can be altered to conceal malicious activity.  Audit data might also provide a means for the malicious user to plan unauthorized activities that exploit weaknesses.
  
The contents of audit logs are protected against unauthorized access, modification, or deletion. Only authorized auditors and the audit functions should be granted Read and Write access to audit log data.'
  desc 'check', 'Obtain the Email Domain Security Plan (EDSP)  and locate the authorized groups or users that should have access to the audit data.

If any group or user has access to the audit data that is not documented in the EDSP, this is a finding.'
  desc 'fix', 'Restrict any unauthorized groups or users from accessing the audit logs.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41718r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33611'
  tag rid: 'SV-44031r1_rule'
  tag stig_id: 'Exch-2-826'
  tag gtitle: 'Exch-2-826'
  tag fix_id: 'F-37503r3_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
