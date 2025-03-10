control 'SV-205460' do
  title 'The Mainframe Product must allow only the information system security manager (ISSM) or individuals or roles appointed by the ISSM to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records."
  desc 'check', 'Examine the configuration settings.

Verify the capability to select auditable events is restricted to security administrators (or individuals or roles appointed by the ISSM). If it is not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to restrict selection of auditable events to   security administrators (or individuals or roles appointed by the ISSM).'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5726r299613_chk'
  tag severity: 'medium'
  tag gid: 'V-205460'
  tag rid: 'SV-205460r395709_rule'
  tag stig_id: 'SRG-APP-000090-MFP-000115'
  tag gtitle: 'SRG-APP-000090'
  tag fix_id: 'F-5726r299614_fix'
  tag 'documentable'
  tag legacy: ['SV-82679', 'V-68189']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
