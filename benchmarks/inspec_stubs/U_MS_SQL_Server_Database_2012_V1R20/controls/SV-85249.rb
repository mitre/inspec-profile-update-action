control 'SV-85249' do
  title 'Appropriate staff must be alerted when the amount of storage space used by the SQL Server transaction log file(s) exceeds an organization-defined value.'
  desc 'It is important for the appropriate personnel to be aware if the system is at risk of failing to record transaction log data.  The transaction log is the heart of a SQL Server database.  If it fails, processing will stop.  It must always have enough available storage space to cope with peak load.  Administrators must be warned about abnormally high space consumption soon enough to take corrective action before all space is used up.'
  desc 'check', 'Review system documentation and/or organizational procedures to determine the threshold value for the storage used by the transaction log, above which staff must be alerted.  The threshold may be expressed as an absolute quantity, or a percentage of total available space.

If this threshold has not been defined, this is a finding.

If monitoring software is in use, and has been configured to alert system and database administrators when the threshold is exceeded, this is not a finding.

If manual procedures exist for frequently checking the space used and alerting system and database administrators, and there is evidence that the procedures are adhered to, this is not a finding.

Otherwise, this is a finding.'
  desc 'fix', 'Decide on, and document, the threshold value for alerting administrators to a shortage of storage for the transaction log.

Establish automated or manual monitoring and alerting.'
  impact 0.3
  ref 'DPMS Target SQL Server Database 2012'
  tag check_id: 'C-71297r2_chk'
  tag severity: 'low'
  tag gid: 'V-70627'
  tag rid: 'SV-85249r2_rule'
  tag stig_id: 'SQL2-00-017510'
  tag gtitle: 'SRG-APP-000144-DB-000101'
  tag fix_id: 'F-77185r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000553']
  tag nist: ['CP-10 (2)']
end
