control 'SV-222933' do
  title 'Cookies must have http-only flag set.'
  desc '<0> [object Object]'
  desc 'check', 'From the Tomcat server console, run the following command:

sudo grep -i -B10 -A1 \\/cookie-config $CATALINA_BASE/conf/web.xml

If the command returns no results or if the <http-only> element is not set to true, this is a finding.

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

If the cookie-config section does not exist it must be added. Add or modify the <http-only> setting and set to true.

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
  tag check_id: 'C-24605r426243_chk'
  tag severity: 'medium'
  tag gid: 'V-222933'
  tag rid: 'SV-222933r879530_rule'
  tag stig_id: 'TCAT-AS-000080'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-24594r426244_fix'
  tag legacy: ['SV-111397', 'V-102449']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
