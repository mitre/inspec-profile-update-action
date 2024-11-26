control 'SV-77425' do
  title 'Riverbed Optimization System (RiOS) must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be logged.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Verify that RiOS restricts permission to select auditable event to authorized administrators.

Navigate to the device Management Console
Navigate to:
Configure >> Security >> User Permissions

Verify the "Deny" attribute is selected for "Basic Diagnostics", "TCP Dumps", "Reports" permissions

If the "Deny" attribute is not set for users who are not authorized access to configure auditable events, this is a finding.'
  desc 'fix', 'Configure RiOS permission for auditable events.

Navigate to the device Management Console, then
Navigate to:
Configure >> Security >> User Permissions

Select the user
For "Basic Diagnostics", "TCP Dumps", "Reports". Click the "Deny" attribute

Click "Save" to save these settings permanently'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63687r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62935'
  tag rid: 'SV-77425r1_rule'
  tag stig_id: 'RICX-DM-000072'
  tag gtitle: 'SRG-APP-000090-NDM-000222'
  tag fix_id: 'F-68853r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
