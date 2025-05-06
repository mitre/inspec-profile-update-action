control 'SV-205471' do
  title 'The Mainframe Product must alert the system administrator (SA) and information system security officer (ISSO) (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', 'If the Mainframe Product does not perform audit data management or storage function, this is not applicable.

Examine configuration settings.

Determine if Mainframe Product alerts system programmers or security administrators in the event of audit processing failure. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to alert system programmers or security administrators in the event of audit processing failure.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5737r299646_chk'
  tag severity: 'medium'
  tag gid: 'V-205471'
  tag rid: 'SV-205471r395802_rule'
  tag stig_id: 'SRG-APP-000108-MFP-000154'
  tag gtitle: 'SRG-APP-000108'
  tag fix_id: 'F-5737r299647_fix'
  tag 'documentable'
  tag legacy: ['SV-82755', 'V-68265']
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
