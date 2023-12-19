control 'SV-84429' do
  title 'Exchange audit data must be protected against unauthorized access for deletion.'
  desc 'Log files help establish a history of activities and can be useful in detecting attack attempts or determining tuning adjustments to improve availability. Audit log content must always be considered sensitive and in need of protection. Audit data available for modification by a malicious user can be altered to conceal malicious activity. Audit data might also provide a means for the malicious user to plan unauthorized activities that exploit weaknesses.
  
The contents of audit logs are protected against unauthorized access, modification, or deletion. Only authorized auditors and the audit functions should be granted read and write access to audit log data.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP). 

Determine the authorized groups or users that should have delete permissions for the audit data.

If any group or user has delete permissions for the audit data that is not documented in the EDSP, this is a finding.'
  desc 'fix', "Update the EDSP.

Restrict any unauthorized groups' or users' delete permissions for the audit logs."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70259r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69807'
  tag rid: 'SV-84429r1_rule'
  tag stig_id: 'EX13-EG-000065'
  tag gtitle: 'SRG-APP-000120'
  tag fix_id: 'F-76019r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
