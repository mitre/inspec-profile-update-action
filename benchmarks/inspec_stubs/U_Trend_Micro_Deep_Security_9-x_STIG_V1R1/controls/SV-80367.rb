control 'SV-80367' do
  title 'Trend Deep Security must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 
 
The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records."
  desc 'check', 'Review the Trend Deep Security server to ensure only the ISSM (or individuals or roles appointed by the ISSM) is allowed to select which auditable events are to be audited.

Verify the user roles and assigned permissions within the Administration >> User Management >> Roles >> Properties >> Other Rights.

If a user role (e.g., Auditor) has any "View Only" for Alerts, Alert Configuration, Integrity Monitoring, and Log Inspection Rules, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to only allow the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.

Configure the assigned permissions for user roles within the 
Administration >> User Management >> Roles >> Properties >> Other Rights. Set the following to "View Only"
Alerts
Alert Configuration
Integrity Monitoring
Log Inspection Rule'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66525r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65877'
  tag rid: 'SV-80367r1_rule'
  tag stig_id: 'TMDS-00-000065'
  tag gtitle: 'SRG-APP-000090'
  tag fix_id: 'F-71953r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
