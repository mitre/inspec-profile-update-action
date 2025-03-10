control 'SV-254086' do
  title 'Innoslate must initiate a session lock after a 15-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their application session prior to vacating the vicinity, applications need to be able to identify when a user's application session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled. This is typically at the operating system-level and results in a system lock, but may be at the application-level where the application interface window is secured instead.

"
  desc 'check', '1. Enter the web.xml file located at C:\\Innoslate4\\apache-tomcat\\webapps\\Innoslate4\\WEB-INF.
2. Search (Ctrl+f) for "session-timeout" object (typically found on line 8).
3. Verify time is set to 15 minutes, if not , this is a finding.'
  desc 'fix', '1. Enter the web.xml file located at C:\\Innoslate4\\apache-tomcat\\webapps\\Innoslate4\\WEB-INF.
2. Search (Ctrl+f) for "session-timeout" object (typically found on line 8).
3. Set the time to 15 minutes.
4. Save.
5. Restart the service.'
  impact 0.5
  ref 'DPMS Target SPEC Innovations Innoslate 4.x'
  tag check_id: 'C-57571r845232_chk'
  tag severity: 'medium'
  tag gid: 'V-254086'
  tag rid: 'SV-254086r845234_rule'
  tag stig_id: 'SPEC-IN-000015'
  tag gtitle: 'SRG-APP-000003'
  tag fix_id: 'F-57522r845233_fix'
  tag satisfies: ['SRG-APP-000003', 'SRG-APP-000190', 'SRG-APP-000390']
  tag 'documentable'
  tag cci: ['CCI-000057', 'CCI-001133', 'CCI-002039']
  tag nist: ['AC-11 a', 'SC-10', 'IA-11']
end
