control 'SV-233039' do
  title 'The container platform must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.
 
The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records."
  desc 'check', 'Review the container platform to determine if the container platform is configured to allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited. 

If the container platform is not configured to only allow the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited, this is a finding.'
  desc 'fix', 'Configure the container platform to only allow the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35975r601614_chk'
  tag severity: 'medium'
  tag gid: 'V-233039'
  tag rid: 'SV-233039r601615_rule'
  tag stig_id: 'SRG-APP-000090-CTR-000155'
  tag gtitle: 'SRG-APP-000090'
  tag fix_id: 'F-35943r600605_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
