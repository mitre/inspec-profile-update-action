control 'SV-76845' do
  title 'ColdFusion must automatically terminate a user session after user inactivity.'
  desc 'An attacker can take advantage of user sessions that are left open, thus bypassing the user authentication process.

To thwart the vulnerability of open and unused user sessions, the application server must be configured to close the sessions when a configured condition or trigger event is met.  Such an event is user inactivity.  ColdFusion offers an inactivity parameter that allows the setting of a system-wide timeout for sessions.  If this parameter is set too large, the usefulness of the parameter is lost.  Care must be taken to not allow sessions to be open longer than needed, but also not set so short that users are unable to use the hosted applications.'
  desc 'check', 'Within the Administrator Console, navigate to the "Memory Variables" page under the "Server Settings" menu.

If the "Session Variables" setting under the "Default Timeout" section is set greater than 15 minutes, this is a finding.'
  desc 'fix', 'Navigate to the "Memory Variables" page under the "Server Settings" menu.  Set the "Session Variables" setting under the "Default Timeout" section to 15 minutes or less and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63159r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62355'
  tag rid: 'SV-76845r1_rule'
  tag stig_id: 'CF11-01-000010'
  tag gtitle: 'SRG-APP-000295-AS-000263'
  tag fix_id: 'F-68275r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
