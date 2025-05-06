control 'SV-241728' do
  title 'tc Server UI must set the useHttpOnly parameter.'
  desc 'A cookie can be read by client-side scripts easily if cookie properties are not set properly. By allowing cookies to be read by the client-side scripts, information such as session identifiers could be compromised and used by an attacker who intercepts the cookie. Setting cookie properties (i.e. HttpOnly property) to disallow client-side scripts from reading cookies better protects the information inside the cookie.

As a Tomcat derivative, tc Server contains a Context object, which represents a web application running within a particular virtual host. One of the configurable parameters of the Context object will prevent the tc Server cookies from being accessed by JavaScript from another site.'
  desc 'check', 'At the command prompt, execute the following command:

grep useHttpOnly /usr/lib/vmware-vcops/tomcat-web-app/webapps/ui/META-INF/context.xml

If the value of “useHttpOnly” is not set to "true" or is missing, this is a finding.

Expected Result:
<Context useHttpOnly="true">'
  desc 'fix', %q(Navigate to and open /usr/lib/vmware-vcops/tomcat-web-app/webapps/ui/META-INF/context.xml.

Navigate to the <Context> node.

Add the 'useHttpOnly="true"' setting to the <Context> node.

Note: The <Context> node should be configured per the below:

<Context useHttpOnly="true">)
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-45004r854953_chk'
  tag severity: 'medium'
  tag gid: 'V-241728'
  tag rid: 'SV-241728r879810_rule'
  tag stig_id: 'VROM-TC-000940'
  tag gtitle: 'SRG-APP-000439-WSR-000154'
  tag fix_id: 'F-44963r684045_fix'
  tag 'documentable'
  tag legacy: ['SV-99741', 'V-89091']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
