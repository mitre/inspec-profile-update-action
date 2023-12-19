control 'SV-259055' do
  title 'The vCenter Lookup service cookies must have "http-only" flag set.'
  desc 'Cookies are a common way to save session state over the HTTP(S) protocol. If attackers can compromise session data stored in a cookie, they are better able to launch an attack against the server and its applications. When a cookie is tagged with the "HttpOnly" flag, it tells the browser this particular cookie should only be accessed by the originating server. Any attempt to access the cookie from client script is strictly forbidden.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/http-only' -

Expected result:

<http-only>true</http-only>

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-lookupsvc/conf/web.xml

Navigate to the <session-config> node and configure the <http-only> as follows:

<session-config>
  <session-timeout>30</session-timeout>
  <cookie-config>
      <http-only>true</http-only>
      <secure>true</secure>
  </cookie-config>
</session-config>

Restart the service with the following command:

# vmon-cli --restart lookupsvc'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Lookup Service'
  tag check_id: 'C-62795r934821_chk'
  tag severity: 'medium'
  tag gid: 'V-259055'
  tag rid: 'SV-259055r934823_rule'
  tag stig_id: 'VCLU-80-000129'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-62704r934822_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
