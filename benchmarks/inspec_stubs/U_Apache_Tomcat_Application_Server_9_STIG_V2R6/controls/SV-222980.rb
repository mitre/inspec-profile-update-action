control 'SV-222980' do
  title 'LockOutRealms must be used for management of Tomcat.'
  desc 'A LockOutRealm adds the ability to lock a user out after multiple failed logins. LockOutRealm is an implementation of the Tomcat Realm interface that extends the CombinedRealm to provide user lock out functionality if there are too many failed authentication attempts in a given period of time. A LockOutRealm is created by wrapping around a standard realm such as a JNDI Directory Realm which connects Tomcat to an LDAP Directory. 

A Catalina container (Engine, Host, or Context) may contain no more than one Realm element (although this one Realm may itself contain multiple nested Realms). In addition, the Realm associated with an Engine or a Host is automatically inherited by lower-level containers unless the lower level container explicitly defines its own Realm. If no Realm is configured for the Engine, an instance of the Null Realm will be configured for the Engine automatically.'
  desc 'check', 'From the Tomcat server console, run the following command:

sudo grep -i  LockOutRealm $CATALINA_BASE/conf/server.xml.  

If there are no results or if the LockOutRealm is not used for the Tomcat management application context, this is a finding.'
  desc 'fix', 'From the Tomcat server console as a privileged user edit the $CATALINA_BASE/conf/server.xml file.

sudo nano $CATALINA_BASE/conf/server.xml file

Locate or add the LockOutRealm element. Make sure the LockOutRealm element is applied to the management application at a minimum (if the management application is in use on the system). This is done by ensuring the LockOutRealm is nested under the Engine, Host or directly within the management application Context container.

EXAMPLE:

      <Realm className="org.apache.catalina.realm.LockOutRealm" failureCount="5" lockOutTime="600">
...
</Realm>'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24652r426384_chk'
  tag severity: 'medium'
  tag gid: 'V-222980'
  tag rid: 'SV-222980r879692_rule'
  tag stig_id: 'TCAT-AS-001020'
  tag gtitle: 'SRG-APP-000315-AS-000094'
  tag fix_id: 'F-24641r426385_fix'
  tag 'documentable'
  tag legacy: ['SV-111483', 'V-102543']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
