control 'SV-228365' do
  title 'Exchange must protect audit data against unauthorized read access.'
  desc 'Log files help establish a history of activities and can be useful in detecting attack attempts or determining tuning adjustments to improve availability. Audit log content must always be considered sensitive and in need of protection. Audit data available for modification by a malicious user can be altered to conceal malicious activity. Audit data might also provide a means for the malicious user to plan unauthorized activities that exploit weaknesses.

The contents of audit logs are protected against unauthorized access, modification, or deletion. Only authorized auditors and the audit functions should be granted "Read" and "Write" access to audit log data.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP) or document that contains this information. 

Determine the authorized groups or users that should have "Read" access to the audit data.

If any group or user has "Read" access to the audit data that is not documented in the EDSP, this is a finding.'
  desc 'fix', %q(Update the EDSP to specify the authorized groups or users that should have "Read" access to the audit data or verify that this information is documented by the organization.

Restrict any unauthorized groups' or users' "Read" access to the audit logs.)
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30598r496891_chk'
  tag severity: 'medium'
  tag gid: 'V-228365'
  tag rid: 'SV-228365r879576_rule'
  tag stig_id: 'EX16-MB-000120'
  tag gtitle: 'SRG-APP-000118'
  tag fix_id: 'F-30583r496892_fix'
  tag 'documentable'
  tag legacy: ['SV-95355', 'V-80645']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
