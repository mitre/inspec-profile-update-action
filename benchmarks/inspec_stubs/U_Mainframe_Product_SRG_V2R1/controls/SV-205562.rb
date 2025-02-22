control 'SV-205562' do
  title 'The Mainframe Product must provide an audit reduction capability that does not alter original content or time ordering of audit records.'
  desc 'If the audit reduction capability alters the content or time ordering of audit records, the integrity of the audit records is compromised, and the records are no longer usable for forensic analysis. Time ordering refers to the chronological organization of records based on time stamps. The degree of time stamp precision can affect this.

Audit reduction is a process that manipulates collected audit information and organizes such information in a summary format that is more meaningful to analysts. 

This requirement is specific to applications with audit reduction capabilities; however, applications need to support on-demand audit review and analysis.'
  desc 'check', 'If the Mainframe Product does not perform audit data management or storage function, this is not applicable.

Examine installation and configuration settings.

Verify the Mainframe Product audit reduction capability does not alter original content or time ordering of audit records. If it does, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product audit reduction capability to not alter original content or time ordering of audit records.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5828r299913_chk'
  tag severity: 'medium'
  tag gid: 'V-205562'
  tag rid: 'SV-205562r851326_rule'
  tag stig_id: 'SRG-APP-000369-MFP-000166'
  tag gtitle: 'SRG-APP-000369'
  tag fix_id: 'F-5828r299914_fix'
  tag 'documentable'
  tag legacy: ['SV-82775', 'V-68285']
  tag cci: ['CCI-001881']
  tag nist: ['AU-7 b']
end
