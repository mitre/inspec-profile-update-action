control 'SV-95831' do
  title 'The Central Log Server must be configured to allow only the Information System Security Manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be retained.'
  desc "Without restricting which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating log records."
  desc 'check', 'Examine the configuration.

Verify the system is configured to allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be retained.

If the Central Log Server is not configured to allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be retained, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be retained.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80771r1_chk'
  tag severity: 'low'
  tag gid: 'V-81117'
  tag rid: 'SV-95831r1_rule'
  tag stig_id: 'SRG-APP-000090-AU-000070'
  tag gtitle: 'SRG-APP-000090-AU-000070'
  tag fix_id: 'F-87889r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
