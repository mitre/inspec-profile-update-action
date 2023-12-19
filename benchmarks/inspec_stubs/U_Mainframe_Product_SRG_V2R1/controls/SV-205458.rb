control 'SV-205458' do
  title 'For Mainframe Products providing audit record aggregation, the Mainframe Product must compile audit records from mainframe components into a system-wide audit trail that is time-correlated with a tolerance for the relationship between time stamps of individual records in the audit trail in accordance with the site security plan.'
  desc 'Without the ability to collate records based on the time when the events occurred, the ability to perform forensic analysis and investigations across multiple components is significantly degraded.

Audit trails are time-correlated if the time stamps in the individual audit records can be reliably related to the time stamps in other audit records to achieve a time ordering of the records within an organization-defined level of tolerance.

This requirement applies only to Mainframe Products that provide the capability to compile system-wide audit records for multiple systems or system components.'
  desc 'check', 'If the Mainframe Product does not perform audit record aggregation, this is not applicable.

Examine configuration settings.

If the Mainframe Product settings do not use the operating system clock for time stamps, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to use the operating system clock for time stamps.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5724r299607_chk'
  tag severity: 'medium'
  tag gid: 'V-205458'
  tag rid: 'SV-205458r864585_rule'
  tag stig_id: 'SRG-APP-000086-MFP-000110'
  tag gtitle: 'SRG-APP-000086'
  tag fix_id: 'F-5724r299608_fix'
  tag 'documentable'
  tag legacy: ['SV-82671', 'V-68181']
  tag cci: ['CCI-000174']
  tag nist: ['AU-12 (1)']
end
