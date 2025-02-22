control 'SV-222961' do
  title 'Applications in privileged mode must be approved by the ISSO.'
  desc "The privileged attribute controls if a context (application) is allowed to use container provided servlets like the Manager servlet. It is false by default and should only be changed for trusted web applications.

Set to true to allow the context (application) to use container servlets, like the manager servlet. Use of the privileged attribute will change the context's parent class loader to be the Server class loader rather than the Shared class loader. Note that in a default installation, the Common class loader is used for both the Server and the Shared class loaders. Use of the privileged attribute will change the context's parent class loader to be the Server class loader rather than the Shared class loader."
  desc 'check', 'Individual Context elements may be explicitly defined in an individual file located at /META-INF/context.xml inside the application files or in the $CATALINA_BASE/conf/context.xml file. It is not recommended to store the context element in the server.xml file as changes will require a server restart.

The $CATALINA_BASE/conf/context element information will be loaded by all web applications, the META-INF/context.xml will only be loaded by that specific application.

On the Tomcat server as a privileged user run the following commands:

grep -i privileged $CATALINA_BASE/conf/context.xml

Repeat the following command for each installed application:

grep -i privileged $CATALINA_BASE/webapps/<application name>META-INF/context.xml

If the privileged context attribute is set to true, confirm the application has been approved for privileged mode by the ISSO. If the application is not approved to run in privileged mode, this is a finding.'
  desc 'fix', 'On the Tomcat server as a privileged user, modify the relevant context.xml file and set the privileged attribute to false (privileged=false).
A restart should not be required if the context element is not maintained in the server.xml file.

If privileged mode is required for a particular application, verify trust of application and obtain documented approval from the ISSO.  Document the applications that are approved to run in privileged mode and retain approvals in the system security plan (SSP) for CCRI reviews.'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24633r426327_chk'
  tag severity: 'medium'
  tag gid: 'V-222961'
  tag rid: 'SV-222961r879588_rule'
  tag stig_id: 'TCAT-AS-000590'
  tag gtitle: 'SRG-APP-000142-AS-000014'
  tag fix_id: 'F-24622r426328_fix'
  tag 'documentable'
  tag legacy: ['SV-111447', 'V-102505']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
