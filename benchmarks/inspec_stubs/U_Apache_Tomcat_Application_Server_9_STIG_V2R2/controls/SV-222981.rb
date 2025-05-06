control 'SV-222981' do
  title 'LockOutRealms failureCount attribute must be set to 5 failed logins for admin users.'
  desc 'A LockOutRealm adds the ability to lock a user out after multiple failed logins. Setting the failureCount attribute to 5 will lock out a user account after 5 failed attempts. 

LockOutRealm is an implementation of the Tomcat Realm interface that extends the CombinedRealm to provide user lock out functionality if there are too many failed authentication attempts in a given period of time. A LockOutRealm is created by wrapping around a standard realm such as a JNDI Directory Realm which connects Tomcat to an LDAP Directory.

A Catalina container (Engine, Host, or Context) may contain no more than one Realm element (although this one Realm may itself contain multiple nested Realms). In addition, the Realm associated with an Engine or a Host is automatically inherited by lower-level containers unless the lower level container explicitly defines its own Realm. If no Realm is configured for the Engine, an instance of the Null Realm will be configured for the Engine automatically.'
  desc 'check', 'From the Tomcat server console, run the following command:

sudo grep -i  LockOutRealm $CATALINA_BASE/conf/server.xml.  

If there are no results or if the LockOutRealm failureCount setting is not configured to 5, this is a finding.'
  desc 'fix', 'From the Tomcat server console as a privileged user edit the $CATALINA_BASE/conf/server.xml file.

sudo nano $CATALINA_BASE/conf/server.xml file

Locate or add the LockOutRealm element. Set LockOutRealm failureCount="5"

EXAMPLE:
      <Realm className="org.apache.catalina.realm.LockOutRealm" failureCount="5" lockOutTime="600">
...
</Realm>'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24653r426387_chk'
  tag severity: 'medium'
  tag gid: 'V-222981'
  tag rid: 'SV-222981r615938_rule'
  tag stig_id: 'TCAT-AS-001030'
  tag gtitle: 'SRG-APP-000316-AS-000199'
  tag fix_id: 'F-24642r426388_fix'
  tag 'documentable'
  tag legacy: ['SV-111485', 'V-102545']
  tag cci: ['CCI-002322']
  tag nist: ['AC-17 (9)']
end
