control 'SV-250340' do
  title 'HTTP session timeout must be configured.'
  desc 'An attacker can take advantage of user sessions that are left open, thus bypassing the user authentication process.

To thwart the vulnerability of open and unused user sessions, the application server must be configured to close the sessions when a configured condition or trigger event is met.

Session termination terminates all processes associated with a user’s logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

'
  desc 'check', 'As a user with access to the server xml file, review the contents and verify the httpSession time out setting is configured for 10 minutes.

If the ${server.config.dir}/server.xml does not define the timeout setting as 10 minutes, this is a finding.

<httpSession invalidationTimeout="10m"/>'
  desc 'fix', 'The ${server.config.dir}/server.xml file must be configured to update the invalidationTimeout attribute on the httpSession element to set the session timeout value in hours (h) or minutes (m). The server.xml file must define the following: 

<httpSession invalidationTimeout="10m"/>  

By default, httpSession invalidationTimeout is set to 30m.'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53775r795071_chk'
  tag severity: 'medium'
  tag gid: 'V-250340'
  tag rid: 'SV-250340r850897_rule'
  tag stig_id: 'IBMW-LS-000720'
  tag gtitle: 'SRG-APP-000295-AS-000263'
  tag fix_id: 'F-53729r795072_fix'
  tag satisfies: ['SRG-APP-000295-AS-000263', 'SRG-APP-000389-AS-000253']
  tag 'documentable'
  tag cci: ['CCI-002038', 'CCI-002361']
  tag nist: ['IA-11', 'AC-12']
end
