control 'SV-80375' do
  title 'Trend Deep Security must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure the ISSO and SA (at a minimum) are alerted in the event of an audit processing failure.

Verify any audit processing failure events within Administration >> System Settings >> System Events, are set to “Forward” 

If these settings are not set to “Forward”, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to alert the ISSO and SA (at a minimum) in the event of an audit processing failure.

Go to Administration >> System Settings >> System Events, and set the following settings to “Forward.”

0 Unknown Error
266 Warnings/Errors Cleared
609 User Made Invalid Request
740 Agent/Appliance Error
801 Error Dismissed
913 Automatic Diagnostic Package Error
923 Usage Information Package Error
997 Tagging Error
998 System Event Notification Error
999 Internal Software Error
1677 Trusted Platform Module Error'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66533r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65885'
  tag rid: 'SV-80375r1_rule'
  tag stig_id: 'TMDS-00-000085'
  tag gtitle: 'SRG-APP-000108'
  tag fix_id: 'F-71961r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
