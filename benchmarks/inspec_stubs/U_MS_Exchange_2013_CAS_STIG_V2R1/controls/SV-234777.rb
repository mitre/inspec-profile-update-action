control 'SV-234777' do
  title 'Exchange must have Audit data protected against unauthorized read access.'
  desc 'Log files help establish a history of activities, and can be useful in detecting attack attempts or determining tuning adjustments to improve availability. Audit log content must always be considered sensitive, and in need of protection. Audit data available for modification by a malicious user can be altered to conceal malicious activity. Audit data might also provide a means for the malicious user to plan unauthorized activities that exploit weaknesses.

The contents of audit logs are protected against unauthorized access, modification, or deletion. Only authorized auditors and the audit functions should be granted Read and Write access to audit log data.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the authorized groups or users that should have read access to the audit data.

If any group or user has read access to the audit data that is not documented in the EDSP, this is a finding.'
  desc 'fix', "Update the EDSP.

Navigate to the location of the audit data.

By default, the logs are located on the application partition in \\Program Files\\Microsoft\\Exchange Server\\V15\\Logging

Restrict any unauthorized groups' or users' read access to the audit logs."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-37963r617270_chk'
  tag severity: 'medium'
  tag gid: 'V-234777'
  tag rid: 'SV-234777r811159_rule'
  tag stig_id: 'EX13-CA-000065'
  tag gtitle: 'SRG-APP-000118'
  tag fix_id: 'F-37926r811158_fix'
  tag 'documentable'
  tag legacy: ['SV-84361', 'V-69739']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
