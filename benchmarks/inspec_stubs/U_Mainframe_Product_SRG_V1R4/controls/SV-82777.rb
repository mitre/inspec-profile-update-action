control 'SV-82777' do
  title 'The Mainframe Product must provide a report generation capability that does not alter original content or time ordering of audit records.'
  desc 'If the audit report generation capability alters the original content or time ordering of audit records, the integrity of the audit records is compromised, and the records are no longer usable for forensic analysis. Time ordering refers to the chronological organization of records based on time stamps. The degree of time stamp precision can affect this.

The report generation capability provided by the application can generate customizable reports. 

This requirement is specific to applications with audit reduction capabilities; however, applications need to support on-demand audit review and analysis.'
  desc 'check', 'If the Mainframe Product does not perform audit data management or storage function, this is not applicable.

Examine installation and configuration settings.

Verify the Mainframe Product report generation does not alter original content or time ordering of audit records. If it does, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product report generation to not alter original content or time ordering of audit records.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68847r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68287'
  tag rid: 'SV-82777r1_rule'
  tag stig_id: 'SRG-APP-000370-MFP-000167'
  tag gtitle: 'SRG-APP-000370-MFP-000167'
  tag fix_id: 'F-74401r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001882']
  tag nist: ['AU-7 b']
end
