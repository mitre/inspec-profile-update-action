control 'SV-89487' do
  title 'The MQ Appliance must automatically terminate a WebGUI user session after 600 seconds of idle time.'
  desc "An attacker can take advantage of WebGUI user sessions that are left open, thus bypassing the user authentication process.

To thwart the vulnerability of open and unused user sessions, the messaging server must be configured to close the sessions when a configured condition or trigger event is met.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use."
  desc 'check', 'Log on to the MQ Appliance CLI as a privileged user.

To access the MQ Appliance CLI, enter:
mqcli

To enter configuration mode, enter:
co
web-mgmt
show

If the idle-timeout value is not "600" seconds or less, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance CLI as a privileged user.

To access the MQ Appliance CLI, enter:
mqcli

To enter configuration mode, enter:
co
web-mgmt
idle-timeout <600 seconds or less>
exit
write mem
y'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74671r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74813'
  tag rid: 'SV-89487r1_rule'
  tag stig_id: 'MQMH-AS-000720'
  tag gtitle: 'SRG-APP-000295-AS-000263'
  tag fix_id: 'F-81429r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
