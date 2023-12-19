control 'SV-205563' do
  title 'The Mainframe Product must provide a report generation capability that does not alter original content or time ordering of audit records.'
  desc 'If the audit report generation capability alters the original content or time ordering of audit records, the integrity of the audit records is compromised, and the records are no longer usable for forensic analysis. Time ordering refers to the chronological organization of records based on time stamps. The degree of time stamp precision can affect this.

The report generation capability provided by the application can generate customizable reports. 

This requirement is specific to applications with audit reduction capabilities; however, applications need to support on-demand audit review and analysis.'
  desc 'check', 'If the Mainframe Product does not perform audit data management or storage function, this is not applicable.

Examine installation and configuration settings.

Verify the Mainframe Product report generation does not alter original content or time ordering of audit records. If it does, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product report generation to not alter original content or time ordering of audit records.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5829r299916_chk'
  tag severity: 'medium'
  tag gid: 'V-205563'
  tag rid: 'SV-205563r851327_rule'
  tag stig_id: 'SRG-APP-000370-MFP-000167'
  tag gtitle: 'SRG-APP-000370'
  tag fix_id: 'F-5829r299917_fix'
  tag 'documentable'
  tag legacy: ['SV-82777', 'V-68287']
  tag cci: ['CCI-001882']
  tag nist: ['AU-7 b']
end
