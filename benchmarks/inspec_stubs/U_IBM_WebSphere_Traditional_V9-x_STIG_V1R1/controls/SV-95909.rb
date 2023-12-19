control 'SV-95909' do
  title 'The WebSphere Application Server admin console session timeout must be configured.'
  desc "An attacker can take advantage of user sessions that are left open, thus bypassing the user authentication process.

To thwart the vulnerability of open and unused user sessions, the application server must be configured to close the sessions when a configured condition or trigger event is met.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use."
  desc 'check', 'Review System Security Plan and system configuration documentation.

Access the Deployment Manager (DMGR) operating system.

Locate the deployment.xml file. The default file location where deployment.xml is installed are provided below.  

UNIX:
/opt/IBM/WebSphere/Profiles/DefaultDmgr01/config/cells/<CELL NAME>/applications/isclite.ear/deployments/isclite/

Windows:
C:\\Program Files\\IBM\\WebSphere\\Profiles\\DefaultDmgr01\\config\\cells\\<CELL NAME>\\applications\\isclite.ear\\deployments\\isclite\\

Search the deployment.xml file for the string, "invalidationtimeout="

UNIX:
grep -i invalidationtimeout $PATH/deployment.xml

Windows:
findstr -I invalidationtimeout= $PATH\\deployment.xml

The value is expressed in minutes and the default value is set to "30 minutes".  

If "invalidationtimeout" is not set to "10 minutes", this is a finding.'
  desc 'fix', 'Locate the deployment.xml file. The default file locations where deployment.xml is installed are provided below.  

UNIX:
/opt/IBM/WebSphere/Profiles/DefaultDmgr01/config/cells/<CELL NAME>/applications/isclite.ear/deployments/isclite/

Windows:
C:\\Program Files\\IBM\\WebSphere\\Profiles\\DefaultDmgr01\\config\\cells\\<CELL NAME>\\applications\\isclite.ear\\deployments\\isclite\\

Make a backup copy of the deployment.xml file.

Edit the deployment.xml file.

Modify the "invalidationtimeout=" value and set to "10".

Restart the DMGR and all the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80865r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81195'
  tag rid: 'SV-95909r1_rule'
  tag stig_id: 'WBSP-AS-000020'
  tag gtitle: 'SRG-APP-000295-AS-000263'
  tag fix_id: 'F-87973r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
