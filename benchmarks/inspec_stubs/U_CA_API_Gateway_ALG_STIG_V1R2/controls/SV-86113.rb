control 'SV-86113' do
  title 'The CA API Gateway must off-load audit records onto a centralized log server in real time.'
  desc 'Off-loading ensures audit information does not get overwritten if the limited audit storage capacity is reached and also protects the audit record in case the system/component being audited is compromised.

Off-loading is a common process in information systems with limited audit storage capacity. The audit storage on the ALG is used only in a transitory fashion until the system can communicate with the centralized log server designated for storing the audit records, at which point the information is transferred. However, DoD requires that the log be transferred in real time, which indicates that the time from event detection to off-loading is seconds or less.

This does not apply to audit logs generated on behalf of the device itself (management).

By default, when the CA API Gateway Server is configured to off-load audit records, they are offloaded in real time. No additional configuration is needed.'
  desc 'check', 'Open the CA API Gateway - Policy Manager.

Select "Tasks" and chose "Manage Log/Audit Sinks". 

Confirm the "ssg" log type is "Syslog". Click "Syslog Settings" and verify the settings for the Centralized Syslog Server are set as defined by the organization.

If the log type is not "Syslog", this is a finding. 

If the centralized syslog server settings are not set as defined by the organization, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager.

Select "Tasks" and chose "Manage Log/Audit Sinks". 

Double-click the "ssg" log and change the "Type:" to "Syslog".

Click "Syslog Settings" and specify the settings for the Centralized Syslog Server as defined by the organization.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71879r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71489'
  tag rid: 'SV-86113r1_rule'
  tag stig_id: 'CAGW-GW-000910'
  tag gtitle: 'SRG-NET-000511-ALG-000051'
  tag fix_id: 'F-77809r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
