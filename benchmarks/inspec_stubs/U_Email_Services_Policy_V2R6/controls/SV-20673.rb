control 'SV-20673' do
  title 'Audit logs must be documented and included in backups.'
  desc 'Log files help establish a history of activities, and can be useful in detecting attack attempts or determining tuning adjustments to improve availability. Audit logs are essential to the investigation and prosecution of unauthorized access to email services software and data. Unless audit logs are available for review, the extent of data compromise may not be determined and the vulnerability exploited may not be discovered. Undiscovered vulnerabilities could lead to additional or prolonged compromise of the data.

Audit records should be backed up not less than weekly on to a different system or media than the system being audited, to ensure preservation of audit history.'
  desc 'check', 'Access the EDSP documentation that describes inclusion of Exchange audit data with the weekly backups. Verify these directories are included in the backup strategy to preserve log history. 

If email audit records are included in backups, this is not a finding.'
  desc 'fix', 'Include email audit records in backups and document the backup strategy in the EDSP.'
  impact 0.5
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-22682r4_chk'
  tag severity: 'medium'
  tag gid: 'V-18880'
  tag rid: 'SV-20673r3_rule'
  tag stig_id: 'EMG3-006 Email'
  tag gtitle: 'EMG3-006 Audit Logs Included in Backups'
  tag fix_id: 'F-19577r4_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'ECTB-1'
end
