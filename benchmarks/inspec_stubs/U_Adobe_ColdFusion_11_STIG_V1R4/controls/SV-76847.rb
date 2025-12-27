control 'SV-76847' do
  title 'ColdFusion must set a maximum session time-out value.'
  desc 'An attacker can take advantage of user sessions that are left open, thus bypassing the user authentication process.

To thwart the vulnerability of open and unused user sessions, the application server must be configured to close the sessions when a configured condition or trigger event is met.  Such an event is user inactivity.  ColdFusion offers an inactivity parameter that allows the setting system-wide for session timeout.  ColdFusion also allows a developer to override the default timeout setting and set a new timeout.  To control how large a developer can set the timeout to, a maximum setting is provided.'
  desc 'check', 'Within the Administrator Console, navigate to the "Memory Variables" page under the "Server Settings" menu.

If the "Session Variables" setting under the "Maximum Timeout" section is set greater than "1" hour, this is a finding.'
  desc 'fix', 'Navigate to the "Memory Variables" page under the "Server Settings" menu.  Set the "Session Variables" setting under the "Maximum Timeout" section to "1" hour or less and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63161r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62357'
  tag rid: 'SV-76847r1_rule'
  tag stig_id: 'CF11-01-000011'
  tag gtitle: 'SRG-APP-000295-AS-000263'
  tag fix_id: 'F-68277r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
