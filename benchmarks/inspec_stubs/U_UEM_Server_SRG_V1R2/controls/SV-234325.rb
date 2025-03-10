control 'SV-234325' do
  title 'The UEM server must be configured to allow only specific administrator roles to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records. 

Satisfies:FMT_SMR.1.1(1) 
Reference:PP-MDM-411058"
  desc 'check', 'Verify the UEM server allows only specific administrator roles to select which auditable events are to be audited.

If the UEM server does not allow only specific administrator roles to select which auditable events are to be audited, this is a finding.'
  desc 'fix', 'Configure the UEM server to be configured to allow only specific administrator roles to select which auditable events are to be audited.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37510r613985_chk'
  tag severity: 'medium'
  tag gid: 'V-234325'
  tag rid: 'SV-234325r879560_rule'
  tag stig_id: 'SRG-APP-000090-UEM-000051'
  tag gtitle: 'SRG-APP-000090'
  tag fix_id: 'F-37475r613986_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
