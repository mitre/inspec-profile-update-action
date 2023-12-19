control 'SV-224761' do
  title 'The ISEC7 EMM Suite must initiate a session lock after a 15-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their application session prior to vacating the vicinity, applications need to be able to identify when a user's application session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled. This is typically at the operating system-level and results in a system lock, but may be at the application-level where the application interface window is secured instead."
  desc 'check', 'Log in to the ISEC7 EMM Console.
Navigate to Administration >> Configuration >> Apache Tomcat.
Validate the session timeout has been set to the correct value.

Alternatively, allow the console to sit for 15 minutes and confirm that you are prompted to login once again when attempting to navigate to a new screen.

If the EMM Console timeout has not been set for 15 minutes or less, this is a finding.'
  desc 'fix', 'Log in to the ISEC7 EMM Console.
Navigate to Administration >> Configuration >> Apache Tomcat.
Set the session timeout to the correct value of 15 minutes or less.'
  impact 0.5
  ref 'DPMS Target ISEC7 Sphere'
  tag check_id: 'C-26452r461539_chk'
  tag severity: 'medium'
  tag gid: 'V-224761'
  tag rid: 'SV-224761r505933_rule'
  tag stig_id: 'ISEC-06-000030'
  tag gtitle: 'SRG-APP-000003'
  tag fix_id: 'F-26440r461540_fix'
  tag 'documentable'
  tag legacy: ['SV-106489', 'V-97385']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
