control 'SV-221211' do
  title 'Exchange Audit data must be protected against unauthorized access (read access).'
  desc 'Log files help establish a history of activities and can be useful in detecting attack attempts or determining tuning adjustments to improve availability. Audit log content must always be considered sensitive and in need of protection. Audit data available for modification by a malicious user can be altered to conceal malicious activity. Audit data might also provide a means for the malicious user to plan unauthorized activities that exploit weaknesses.
  
The contents of audit logs are protected against unauthorized access, modification, or deletion. Only authorized auditors and the audit functions should be granted read and write access to audit log data.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the authorized groups or users that should have read access to the audit data.

If any group or user has read access to the audit data that is not documented in the EDSP, this is a finding.'
  desc 'fix', "Update the EDSP to reflect the authorized groups or users that should have read access to the audit data.

Restrict any unauthorized groups' or users' read access to the audit logs."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22926r411759_chk'
  tag severity: 'medium'
  tag gid: 'V-221211'
  tag rid: 'SV-221211r612603_rule'
  tag stig_id: 'EX16-ED-000100'
  tag gtitle: 'SRG-APP-000118'
  tag fix_id: 'F-22915r411760_fix'
  tag 'documentable'
  tag legacy: ['V-80503', 'SV-95213']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
