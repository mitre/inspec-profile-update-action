control 'SV-89479' do
  title 'The MQ Appliance messaging server must automatically terminate a SSH user session after organization-defined conditions or trigger events requiring a session disconnect.'
  desc "An attacker can take advantage of CLI user sessions that are left open, thus bypassing the user authentication process.

To thwart the vulnerability of open and unused user sessions, the messaging server must be configured to close the sessions when a configured condition or trigger event is met.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use."
  desc 'check', 'To access the MQ Appliance CLI, enter:
mqcli

show rbm

Verify that the cli-timeout displays the approved timeout value of 600 seconds (10 minutes) or less.

If it does not, this is a finding.'
  desc 'fix', 'For the CLI used by the administrator, log on to the MQ Appliance CLI as a privileged user.

Enter:
co
rbm
cli-timeout 600
exit
write mem
y'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74663r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74805'
  tag rid: 'SV-89479r1_rule'
  tag stig_id: 'MQMH-AS-000680'
  tag gtitle: 'SRG-APP-000295-AS-000263'
  tag fix_id: 'F-81421r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
