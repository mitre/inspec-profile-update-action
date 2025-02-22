control 'SV-224774' do
  title 'The ISEC7 EMM Suite must configure the timeout for the console to be 15 minutes or less.'
  desc "A session time-out lock is a temporary action taken when a user (MDM system administrator) stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their application session prior to vacating the vicinity, applications need to be able to identify when a user's application session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled. This is typically at the operating system level and results in a system lock but may be at the application level where the application interface window is secured instead."
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
  tag check_id: 'C-26465r461578_chk'
  tag severity: 'medium'
  tag gid: 'V-224774'
  tag rid: 'SV-224774r505933_rule'
  tag stig_id: 'ISEC-06-002520'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-26453r461579_fix'
  tag 'documentable'
  tag legacy: ['V-97263', 'SV-106377']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
