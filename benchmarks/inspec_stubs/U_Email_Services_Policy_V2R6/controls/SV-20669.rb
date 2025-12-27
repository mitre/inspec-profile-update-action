control 'SV-20669' do
  title 'Automated audit reporting tools must be available.'
  desc 'Monitors are automated “process watchers” that respond to performance changes, and can be useful in detecting outages and alerting administrators where attention is needed. Log files help establish a history of activities, and can be useful in detecting attack attempts or determining tuning adjustments to improve availability. However, audit record collection may quickly overwhelm storage resources and an auditor’s ability to review it in a productive manner. Add to that, an audit trail that is not monitored for detection of suspicious activities provides little value. Regular or daily review of audit logs not only leads to the earliest possible notice of a compromise, but can also minimize the extent of the compromise. 

Automated Log Monitoring gives the additional boost to the monitoring process, in that noteworthy events are more immediately detected, provided they have been defined to the automated monitoring process. Log data can be mined for specific events, and upon detection, they can be analyzed to provide choices for alert methods, reports, trend analyses, attack scenario solutions.'
  desc 'check', 'Access the EDSP for description of automated audit trail review tool.  Review automated tool usage artifacts or reports with audit trail result data.

If automated tools are available for review and reporting on email server audit records, this is not a finding.'
  desc 'fix', 'Implement automated reporting tools for Email Server audit records.  Document the specifics in the EDSP.'
  impact 0.5
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-22523r2_chk'
  tag severity: 'medium'
  tag gid: 'V-18878'
  tag rid: 'SV-20669r3_rule'
  tag stig_id: 'EMG3-079 EMail'
  tag gtitle: 'EMG3-079 Automated Audit Reporting Tool'
  tag fix_id: 'F-19576r2_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'ECRG-1'
end
