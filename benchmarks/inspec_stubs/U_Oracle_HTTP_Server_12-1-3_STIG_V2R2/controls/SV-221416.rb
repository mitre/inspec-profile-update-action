control 'SV-221416' do
  title 'The Node Manager account password associated with the installation of OHS must be in accordance with DoD guidance for length, complexity, etc.'
  desc 'During installation of the web server software, accounts are created for the web server to operate properly. The accounts installed can have either no password installed or a default password, which will be known and documented by the vendor and the user community.

The first things an attacker will try when presented with a login screen are the default user identifiers with default passwords. Installed applications may also install accounts with no password, making the login even easier. Once the web server is installed, the passwords for any created accounts should be changed and documented. The new passwords must meet the requirements for all passwords, i.e., upper/lower characters, numbers, special characters, time until change, reuse policy, etc. 

Service accounts or system accounts that have no login capability do not need to have passwords set or changed.'
  desc 'check', '1. If the password for Node Manager does not meet DoD requirements for password complexity, this is a finding.

2. Open $DOMAIN_HOME/config/nodemanager/nm_password.properties with an editor.

3. If the "username" property and value are still present, this is a finding.

4. If the "password" property and value are still present, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/nodemanager/nm_password.properties with an editor.

2. Remove the "hashed" property and value.

3. Set the "username" property to the account name to use for Node Manager, add the property if it does not exist.

4. Set the "password" property to a password compliant with DoD requirements for password complexity to use for Node Manager, add the property if it does not exist.

5. Start/Restart Node Manager so that the password contained within $DOMAIN_HOME/config/nodemanager/nm_password.properties is encrypted.

6. Remove the "username" and "password" properties and along with their values from within $DOMAIN_HOME/config/nodemanager/nm_password.properties, but leave the new "hashed" property and value.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23131r414931_chk'
  tag severity: 'medium'
  tag gid: 'V-221416'
  tag rid: 'SV-221416r879887_rule'
  tag stig_id: 'OH12-1X-000176'
  tag gtitle: 'SRG-APP-000516-WSR-000079'
  tag fix_id: 'F-23120r414932_fix'
  tag 'documentable'
  tag legacy: ['SV-79083', 'V-64593']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
