control 'SV-224765' do
  title 'The ISEC7 EMM Suite must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', 'Login to the ISEC7 EMM Suite console.
Navigate to Administration >> Configuration >> Notifications >> Recipient Lists.
Select Edit next to the Systems Notifications.
Verify the email address or distribution list has been added.

If a recipient email address or distribution list has not been added to System Notifications, this is a finding.'
  desc 'fix', 'Login to the ISEC7 EMM Suite console.
Navigate to Administration >> Configuration >> Notifications >> Recipient Lists.
Select Edit next to the Systems Notifications.
Under Add recipient, select Email as the Type and enter the correct email address of recipients.
Select Add.'
  impact 0.5
  ref 'DPMS Target ISEC7 Sphere'
  tag check_id: 'C-26456r461551_chk'
  tag severity: 'medium'
  tag gid: 'V-224765'
  tag rid: 'SV-224765r505933_rule'
  tag stig_id: 'ISEC-06-000380'
  tag gtitle: 'SRG-APP-000108'
  tag fix_id: 'F-26444r461552_fix'
  tag 'documentable'
  tag legacy: ['V-97393', 'SV-106497']
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
