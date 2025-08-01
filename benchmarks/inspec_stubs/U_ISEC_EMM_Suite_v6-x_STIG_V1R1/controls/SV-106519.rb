control 'SV-106519' do
  title 'The Manager Web app password must be configured as follows: -15 or more characters -at least one lower case letter -at least one upper case letter -at least one number -at least one special character'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. 

Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.

'
  desc 'check', 'Verify the Manager Web app password has been configured as follows:
-15 or more characters
-at least one lower case letter
-at least one upper case letter
-at least one number
-at least one special character

Login to the ISEC7 EMM Suite server.
Open a Web browser and go to https://localhost/manager/html
Login with the custom administrator login and password. Verify password entered meets complexity requirements.

If the Manager Web app password has not been configured as required, this is a finding.'
  desc 'fix', %q(To set a strong password on the Manager Web app, run the ISEC7 integrated installer or use the following manual procedure:

Login to the ISEC7 EMM Suite server.
Browse to <Drive>:\Program Files\ISEC7 EMM Suite\Tomcat\conf and open Tomcat-Users.xml
Open the Command Prompt and CD to <Drive>:\Program Files\ISEC7 EMM Suite\Tomcat\bin
Execute the following using 'sha' command:

digest –a sha password*

*where password is the 15 character password designated for the account

Copy the output, which is the hashed digest password.
In Tomcat-Users.xml, add in the password for the user with the obfuscated output at <user password="**", where ** is the obfuscated password.

example: <user password="310c55aa3d5b42217e7f0e80ce30467d$100000$529cceb1fbc80f4f461fc1bd56219d79d9c94d4a8fc46abad0646f27e753ff9e" roles="manager-gui,manager-script" username="admin"/>

Save the file.
Open <Drive>:\Program Files\ISEC7 EMM Suite\Tomcat\conf\server.xml with Notepad.exe
Enter: <Realm className="org.apache.catalina.realm.UserDatabaseRealm"
 resourceName="UserDatabase" digest=”sha”/>
Save the file.
Restart the ISEC7 EMM Suite Web service using the services.msc

Note: the password must meet the following complexity requirements:
-15 or more characters
-at least one lower case letter
-at least one upper case letter
-at least one number
-at least one special character)
  impact 0.5
  ref 'DPMS Target ISEC7 EMM Suite v6.x'
  tag check_id: 'C-96251r1_chk'
  tag severity: 'medium'
  tag gid: 'V-97415'
  tag rid: 'SV-106519r1_rule'
  tag stig_id: 'ISEC-06-550700'
  tag gtitle: 'SRG-APP-000164'
  tag fix_id: 'F-103093r1_fix'
  tag satisfies: ['SRG-APP-000164', 'SRG-APP-000166', 'SRG-APP-000169']
  tag 'documentable'
  tag cci: ['CCI-000192', 'CCI-000205', 'CCI-001619']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)']
end
