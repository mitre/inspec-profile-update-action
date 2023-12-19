control 'SV-100721' do
  title 'tc Server VCAC document directory must be in a separate partition from the web servers system files.'
  desc "A web server is used to deliver content on the request of a client. The content delivered to a client must be controlled, allowing only hosted application files to be accessed and delivered. To allow a client access to system files of any type is a major security risk that is entirely avoidable. Obtaining such access is the goal of directory traversal and URL manipulation vulnerabilities. To facilitate such access by misconfiguring the web document (home) directory is a serious error. In addition, having the path on the same drive as the system folder compounds potential attacks such as drive space exhaustion.

As a Tomcat derivative, tc Server stores the web applications in a special 'webapps' folder. The Java engine, however, is stored in a separate are of the OS directory structure. For greatest security It is important to verify that the webapps and the Java directories remain separated."
  desc 'check', 'At the command prompt, execute the following commands:

df -k /usr/java/jre-vmware
df -k /usr/lib/vcac/server/webapps

If the two directories above are on the same partition, this is a finding.'
  desc 'fix', 'Consult with the ISSO. 

Move the tc Server VCAC /usr/lib/vcac/server/webapps folder to a separate partition.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89763r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90071'
  tag rid: 'SV-100721r1_rule'
  tag stig_id: 'VRAU-TC-000590'
  tag gtitle: 'SRG-APP-000233-WSR-000146'
  tag fix_id: 'F-96813r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
