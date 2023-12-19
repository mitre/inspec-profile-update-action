control 'SV-207278' do
  title 'Exchange must protect audit data against unauthorized read access.'
  desc 'Log files help establish a history of activities and can be useful in detecting attack attempts or determining tuning adjustments to improve availability. Audit log content must always be considered sensitive and in need of protection. Audit data available for modification by a malicious user can be altered to conceal malicious activity. Audit data might also provide a means for the malicious user to plan unauthorized activities that exploit weaknesses.
  
The contents of audit logs are protected against unauthorized access, modification, or deletion. Only authorized auditors and the audit functions should be granted Read and Write access to audit log data.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP). 

Determine the authorized groups or users that should have read access to the audit data.

If any group or user has read access to the audit data that is not documented in the EDSP, this is a finding.'
  desc 'fix', "Update the EDSP.

Restrict any unauthorized groups' or users' read access to the audit logs."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7536r393347_chk'
  tag severity: 'medium'
  tag gid: 'V-207278'
  tag rid: 'SV-207278r615936_rule'
  tag stig_id: 'EX13-MB-000060'
  tag gtitle: 'SRG-APP-000118'
  tag fix_id: 'F-7536r393348_fix'
  tag 'documentable'
  tag legacy: ['SV-84585', 'V-69963']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
