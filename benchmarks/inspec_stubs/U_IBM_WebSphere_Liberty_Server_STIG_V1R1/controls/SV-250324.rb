control 'SV-250324' do
  title 'Security cookies must be set to HTTPOnly.'
  desc '<0> [object Object]'
  desc 'check', 'As a user with local file access to ${server.config.dir}/server.xml, verify appSecurity feature is enabled.

<featureManager><feature>appSecurity-3.0</feature></featureManager>

Verify both web application LTPA and http session cookies are configured for httpOnly.

<webAppSecurity  ssoCookieName="LtpaToken2"  ssoRequiresSSL="true"    httpOnlyCookies="true"   logoutOnHttpSessionExpire="true"/>  

<httpSession    cookieName="JSESSIONID"    cookieSecure="true"    cookieHttpOnly="true"    cookiePath="/"/>

If the appSecurity feature is not enabled or if the LPTA or Session cookie settings are not set for httpOnly, this is a finding.'
  desc 'fix', 'To ensure security cookies use httpOnly, the ${server.config.dir)/server.xml must be configured as follows: 

<featureManager><feature>appSecurity-3.0</feature></featureManager>

 <webAppSecurity  ssoCookieName="LtpaToken2"  ssoRequiresSSL="true"    httpOnlyCookies="true"   logoutOnHttpSessionExpire="true"/>  

<httpSession    cookieName="JSESSIONID"    cookieSecure="true"    cookieHttpOnly="true"    cookiePath="/"/>'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53759r795023_chk'
  tag severity: 'medium'
  tag gid: 'V-250324'
  tag rid: 'SV-250324r795110_rule'
  tag stig_id: 'IBMW-LS-000030'
  tag gtitle: 'SRG-APP-000015-AS-000010'
  tag fix_id: 'F-53713r795024_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
