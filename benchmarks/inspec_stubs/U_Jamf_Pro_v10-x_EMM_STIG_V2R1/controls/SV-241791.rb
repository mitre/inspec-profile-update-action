control 'SV-241791' do
  title 'The Jamf Pro EMM server or platform must be configured to initiate a session lock after a 15-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user (MDM system administrator) stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their application session prior to vacating the vicinity, applications need to be able to identify when a user's application session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled. This is typically at the operating system level and results in a system lock but may be at the application level where the application interface window is secured instead.

SFR ID: FMT_SMF.1.1(2) i"
  desc 'check', 'Verify the Jamf Pro EMM server or platform is configured to initiate a session lock after a 15-minute period of inactivity.

Review the variable in the Jamf Pro web.xml file.

On the Jamf Pro host server, open the web.xml file:

If using macOS, the web.xml file is located at the following filepath:
/Library/JSS/Tomcat/webapps/ROOT/WEB-INF/

If using Windows, the web.xml file is located at the following filepath:
C:\\Program Files\\JSS\\Tomcat\\webapps\\ROOT\\WEB-INF\\

If using Linux, the web.xml file is located at the following filepath:
/usr/local/jss/tomcat/webapps/ROOT/WEB-INF/

Locate the following setting:
<session-config>
<session-timeout>15</session-timeout> 
</session-config>

Ensure that the code is not commented out. If the code is commented out, remove the comment tags <!--  --> that encase the code.
Note: Session timeout is in minutes.

If the code is commented out or session-timeout is not configured to "15" minutes or less, this is a finding.'
  desc 'fix', 'Perform the following procedure to configure the Jamf session lock to lock after a 15-minute period of inactivity.

Configuring the Variable in the JAMF web.xml File

On the  Jamf Pro EMM host server, open the web.xml file:

If using macOS, the web.xml file is located at the following filepath:
/Library/JSS/Tomcat/webapps/ROOT/WEB-INF/

If using Windows, the web.xml file is located at the following filepath:
C:\\Program Files\\JSS\\Tomcat\\webapps\\ROOT\\WEB-INF\\

If using Linux, the web.xml file is located at the following filepath:
/usr/local/jss/tomcat/webapps/ROOT/WEB-INF/

Locate the following setting:
<session-config>
<session-timeout>1</session-timeout> 
</session-config>

Ensure that the code is not commented out. If the code is commented out, remove the comment tags <!--  -->  that encase the code.

Modify the session-timeout to a value from 1 to 15.
Note: Session timeout is in minutes.

Restart Tomcat after modifying anything within the web.xml file.
See Starting and Stopping Tomcat for instructions in the Jamf admin guide.'
  impact 0.5
  ref 'DPMS Target Jamf Pro v10-x EMM'
  tag check_id: 'C-45067r685125_chk'
  tag severity: 'medium'
  tag gid: 'V-241791'
  tag rid: 'SV-241791r879513_rule'
  tag stig_id: 'JAMF-10-000460'
  tag gtitle: 'PP-MDM-411047'
  tag fix_id: 'F-45026r685126_fix'
  tag 'documentable'
  tag legacy: ['SV-108675', 'V-99571']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
