control 'SV-222484' do
  title 'Applications categorized as having a moderate or high impact must provide an immediate real-time alert to the SA and ISSO (at a minimum) for all audit failure events.'
  desc 'Applications that are categorized as having a high or moderate impact on the organization must provide immediate alerts when encountering failures with the application audit system.  It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

While alerts provide organizations with urgent messages containing important information regarding application audit log activity, real-time alerts provide these messages at information technology speed (i.e., the time from event detection to alert occurs in seconds or no more than 1-2 minutes).  

Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.'
  desc 'check', 'Review system documentation and interview application administrator for details regarding application security categorization and logging configuration.

If the application utilizes a centralized logging system that provides the real-time alarms, this requirement is not applicable.

Review application log alert configuration.

Identify audit failure events and associated alarming configuration.

If the application is categorized as having a moderate or high impact and is not configured to provide a real-time alert that indicates the audit system has failed or is failing, this is a finding.'
  desc 'fix', 'Configure the log alerts to send an alarm when the audit system is in danger of failing or has failed.  

Configure the log alerts to be immediately sent to the application admin/SA and ISSO.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24154r493360_chk'
  tag severity: 'medium'
  tag gid: 'V-222484'
  tag rid: 'SV-222484r508029_rule'
  tag stig_id: 'APSC-DV-001100'
  tag gtitle: 'SRG-APP-000360'
  tag fix_id: 'F-24143r493361_fix'
  tag 'documentable'
  tag legacy: ['SV-84073', 'V-69451']
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
