control 'SV-222932' do
  title 'Cookies must have secure flag set.'
  desc '<0> [object Object]'
  desc 'check', 'From the Tomcat server console, run the following command:

sudo grep -i -B10 -A1 \\/cookie-config $CATALINA_BASE/conf/web.xml

If the command returns no results or if the <secure> element is not set to true, this is a finding.

EXAMPLE:
<session-config>
   <session-timeout>15</session-timeout>
     <cookie-config>
       <http-only>true</http-only>
        <secure>true</secure>
     </cookie-config>
</session-config>'
  desc 'fix', 'From the Tomcat server console as a privileged user:

edit the $CATALINA_BASE/conf/web.xml

If the cookie-config section does not exist it must be added. Add or modify the <secure> setting and set to true.

EXAMPLE:
<session-config>
   <session-timeout>15</session-timeout>
     <cookie-config>
       <http-only>true</http-only>
        <secure>true</secure>
     </cookie-config>
</session-config>'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24604r426240_chk'
  tag severity: 'medium'
  tag gid: 'V-222932'
  tag rid: 'SV-222932r879530_rule'
  tag stig_id: 'TCAT-AS-000070'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-24593r426241_fix'
  tag legacy: ['SV-111395', 'V-102447']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
