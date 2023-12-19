control 'SV-240869' do
  title 'tc Server HORIZON must set the useHttpOnly parameter.'
  desc 'A cookie can be read by client-side scripts easily if cookie properties are not set properly. By allowing cookies to be read by the client-side scripts, information such as session identifiers could be compromised and used by an attacker who intercepts the cookie. Setting cookie properties (i.e. HttpOnly property) to disallow client-side scripts from reading cookies better protects the information inside the cookie.

As a Tomcat derivative, tc Server contains a Context object, which represents a web application running within a particular virtual host. One of the configurable parameters of the Context object will prevent the tc Server cookies from being accessed by JavaScript from another site.'
  desc 'check', 'At the command prompt, execute the following command:

grep useHttpOnly /opt/vmware/horizon/workspace/conf/context.xml

If the value of "useHttpOnly" is not set to "true" or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /opt/vmware/horizon/workspace/conf/context.xml.

Navigate to the <Context> node.

Add the 'useHttpOnly="true"' setting to the <Context> node.

Note: The <Context> node should be configured per the following:

<Context useHttpOnly="true">)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44102r674349_chk'
  tag severity: 'medium'
  tag gid: 'V-240869'
  tag rid: 'SV-240869r879810_rule'
  tag stig_id: 'VRAU-TC-000885'
  tag gtitle: 'SRG-APP-000439-WSR-000154'
  tag fix_id: 'F-44061r674350_fix'
  tag 'documentable'
  tag legacy: ['SV-100817', 'V-90167']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
