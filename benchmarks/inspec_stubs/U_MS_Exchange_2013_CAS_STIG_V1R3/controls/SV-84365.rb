control 'SV-84365' do
  title 'Exchange must have Audit data protected against unauthorized modification.'
  desc 'Log files help establish a history of activities, and can be useful in detecting attack attempts or determining tuning adjustments to improve availability. Audit log content must always be considered sensitive, and in need of protection. Audit data available for modification by a malicious user can be altered to conceal malicious activity. Audit data might also provide a means for the malicious user to plan unauthorized activities that exploit weaknesses.

The contents of audit logs are protected against unauthorized access, modification, or deletion. Only authorized auditors and the audit functions should be granted Read and Write access to audit log data.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the authorized groups or users that should have access to the audit data.

If any group or user has modify privileges for the audit data that is not documented in the EDSP, this is a finding.'
  desc 'fix', "Update the EDSP.

Navigate to the location of the audit data.

Restrict any unauthorized groups' or users' modify permissions for the audit logs."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-70187r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69743'
  tag rid: 'SV-84365r1_rule'
  tag stig_id: 'EX13-CA-000075'
  tag gtitle: 'SRG-APP-000119'
  tag fix_id: 'F-75949r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
