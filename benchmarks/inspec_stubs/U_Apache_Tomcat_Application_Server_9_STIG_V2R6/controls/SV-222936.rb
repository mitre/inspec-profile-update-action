control 'SV-222936' do
  title 'The Java Security Manager must be enabled.'
  desc "The Java Security Manager (JSM) is what protects the Tomcat server from trojan servlets, JSPs, JSP beans, tag libraries, or even from inadvertent mistakes. The JSM works the same way a client's web browser isolates a running web application via a sandbox, the difference being the sandbox is running on the server rather than the client. To ensure application operability, JSM security policies must be set to allow the hosted application access to the underlying system based on individual application requirements. The JSM settings cannot be determined at the STIG level and will vary based on each hosted application.

Examples include setting JSM policy to allow an application to write to folders on the server or to initiate network connections to other servers via TCP/IP.

Because the JSM isolates application code to prevent an application from adversely accessing resources on the underlying Tomcat server, care must be taken to ensure the JSM policies are configured properly. Allowing untrusted web applications to run on the Tomcat server without a JSM policy that limits access to server resources creates a risk of compromise to the server. 

Ideally, the JSM policy is implemented and tested during the application development phase. This is when the application resource requirements are best identified and documented so the correct JSM policy can be implemented in the production environment.  

Creating the correct JSM policy can be a challenge when installing commercial software that does not provide the policy as part of the installation process or via documentation. This is due to the fact that the critical application access requirements to the system will typically not be known to the system administrator. In these cases, running the JSM can result in failure for some application functionality (e.g., an application might not be able to write logs to a particular folder on the system or communicate with other systems as intended). 

When faced with application functionality failures, the typical troubleshooting approach for the system administrator to follow is to install the application in a test environment, set the $CATALINA_POLICY setting to debug, and identify failure events in the logs. This can aid in identifying what privileges the application requires. From there the JSM policies can be set, tested, documented, and transferred to production. If these actions do not address all of the issues, the Risk Management Framework processes come into effect and a risk acceptance for this requirement must be obtained from the ISSO.

For additional technical information on the security manager and available JSM policy settings, refer to the Security Manager How-To on the Apache Tomcat version 9 website."
  desc 'check', 'Review system documentation. Identify the tomcat systemd startup file which for STIG purposes is called "tomcat.service" and can be viewed as a link in the /etc/systemd/system/ folder.

Run the following command:
sudo cat /etc/systemd/system/tomcat.service |grep -i security

If there is a documented and approved risk acceptance for not operating the Security Manager, the finding can be reduced to a CAT III.
 
If the ExecStart parameter does not include the -security flag, this is a finding.'
  desc 'fix', 'Refer to the vulnerability discussion of this requirement for additional information. Install the application in a test environment and determine the application access requirements. Test and document the Java Security Manager policy and then transfer the JSM policy to the $CATALINA_BASE/conf/catalina.properties file. If operating multiple instances of Tomcat, use $CATALINA_BASE in place of $CATALINA_HOME as per standard Tomcat practice.

As an admin user on the Tomcat server, modify the /etc/systemd/system/tomcat.service file and set the "ExecStart" parameter to read:
"ExecStart=/opt/tomcat/bin/startup.sh -security"

sudo systemctl restart tomcat
sudo systemctl daemon-reload'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24608r426252_chk'
  tag severity: 'medium'
  tag gid: 'V-222936'
  tag rid: 'SV-222936r879530_rule'
  tag stig_id: 'TCAT-AS-000110'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-24597r426253_fix'
  tag 'documentable'
  tag legacy: ['SV-111403', 'V-102455']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
