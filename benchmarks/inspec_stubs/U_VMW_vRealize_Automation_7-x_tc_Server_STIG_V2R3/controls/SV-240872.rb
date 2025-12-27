control 'SV-240872' do
  title 'tc Server HORIZON must set the secure flag for cookies.'
  desc 'Cookies can be sent to a client using TLS/SSL to encrypt the cookies, but TLS/SSL is not used by every hosted application since the data being displayed does not require the encryption of the transmission. To safeguard against cookies, especially session cookies, being sent in plaintext, a cookie can be encrypted before transmission. To force a cookie to be encrypted before transmission, the cookie Secure property can be set.

As a Tomcat derivative, tc Server is based in part on the Java Servlet specification. Servlet 3.0 (Java EE 6) introduced a standard way to configure secure attribute for the session cookie, this can be done by applying the correct configuration in web.xml.'
  desc 'check', %q(At the command prompt, execute the following command:

grep -E '<secure>' /opt/vmware/horizon/workspace/conf/web.xml

If the value of the <secure> node is not set to "true" or is missing, this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/horizon/workspace/conf/web.xml.

Navigate to the <session-config> node.

Add the <cookie-config> --> <secure> node setting to the <session-config> node.

Note: The <cookie-config> --> <secure> node should be configured per the following:

 <cookie-config>
 <secure>true</secure>
 </cookie-config>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44105r674358_chk'
  tag severity: 'medium'
  tag gid: 'V-240872'
  tag rid: 'SV-240872r879810_rule'
  tag stig_id: 'VRAU-TC-000900'
  tag gtitle: 'SRG-APP-000439-WSR-000155'
  tag fix_id: 'F-44064r674359_fix'
  tag 'documentable'
  tag legacy: ['SV-100823', 'V-90173']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
