control 'SV-76911' do
  title 'The ColdFusion built-in TomCat Web Server must be disabled.'
  desc 'Application servers provide a myriad of differing processes, features, and functionalities. Some of these processes may be deemed to be unnecessary or too unsecure to run on a production DoD system.  The built-in TomCat Web Server is used to host the Administrator Console and is used for initial setup.  While the built-in server can be used to continually host the Administrator Console, this is not the best practice since the server is not guaranteed to be patched and upgraded, implementing TLS is not well documented, allowing for poor implementations, and commercial web servers offer better logging.  To enable the Administrator Console to still operate and disable the built-in TomCat Web Server, the Administrator Console application must be moved to the web server (i.e., IIS, Apache, IBM HTTP Server, etc.) hosting the ColdFusion applications.  Moving the Administrator Console to Apache and IIS is well documented in the Adobe ColdFusion Lockdown Guide.'
  desc 'check', 'Locate the server.xml file for ColdFusion.  This file can usually be located under the ColdFusion installation directory under the runtime/conf directory for Linux and runtime\\conf for Windows.  Within the server.xml file, locate the xml line:

<Connector executor="tomcatThreadPool" maxThreads="50"
port="8500" protocol="org.apache.coyote.http11.Http11Protocol"
connectionTimeout="20000"
redirectPort="8445" />

Note: port="8500" is the port the Administrator Console was hosted on.  The port is defined during the install and can be changed from the default of 8500, so this parameter may be different if an alternate port was assigned.

If the line exists and is not commented out (XML comments start with <!-- and end with -->, e.g., <!-- XML COMMENT -->), this is a finding.'
  desc 'fix', 'Locate the server.xml file for ColdFusion.  This file can usually be located under the ColdFusion installation directory under the runtime/conf directory for Linux and runtime\\conf for Windows.  After making a backup of this file, edit the file and locate the following xml line:

<Connector executor="tomcatThreadPool" maxThreads="50"
port="8500" protocol="org.apache.coyote.http11.Http11Protocol"
connectionTimeout="20000"
redirectPort="8445" />

Note: port="8500" is the port the Administrator Console was hosted on.  The port is setup at install and can be changed, so this parameter may be different in this line.

This line can be deleted or using XML syntax can be commented out of the configuration.  XML comment syntax starts with <!-- and ends with -->, e.g., <!-- XML COMMENT -->.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63225r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62421'
  tag rid: 'SV-76911r1_rule'
  tag stig_id: 'CF11-03-000104'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-68341r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
