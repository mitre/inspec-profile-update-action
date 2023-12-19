control 'SV-224769' do
  title 'The ISEC7 EMM Suite must accept Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12, as well as a primary component of layered protection for national security systems.'
  desc 'check', 'Log in to the ISEC7 EMM Console.

Navigate to Administration >> Configuration >> Settings.

Verify the CAC login box has been checked.

On the ISEC7 EMM Suite server, browse to the install directory.
Default is %Install Drive%/Program Files/ISEC7 EMM Suite
Select the conf folder.
Open config.properties and confirm the following lines exist:

    cacUserUIDRegex=^CN=[^0-9]*\\\\.([0-9]+),
    cacUserUIDProperty=UserPrincipalName

Browse to %Install Drive%/Program Files >> ISEC7 EMM Suite >> Tomcat >> conf
Confirm the server.xml file has clientAuth="required" under the Connection.

If the required commends do not exist in config.properties or if clientAuth does not ="required" in the server.xml file, this is a finding.'
  desc 'fix', 'Log in to the ISEC7 EMM Console.

Navigate to Administration >> Configuration >> Settings.
Check the CAC login box.
On the ISEC7 EMM Suite server, browse to the install directory.
Default is %Install Drive%/Program Files/ISEC7 EMM Suite.
Select the conf folder.
Open config.properties and add the following lines:

    cacUserUIDRegex=^CN=[^0-9]*\\\\.([0-9]+),
    cacUserUIDProperty=UserPrincipalName

Browse to %Install Drive%/Program Files >> ISEC7 EMM Suite >> Tomcat >> conf
Open the server.xml file and add clientAuth="required" under the Connection.'
  impact 0.3
  ref 'DPMS Target ISEC7 Sphere'
  tag check_id: 'C-26460r461563_chk'
  tag severity: 'low'
  tag gid: 'V-224769'
  tag rid: 'SV-224769r505933_rule'
  tag stig_id: 'ISEC-06-001730'
  tag gtitle: 'SRG-APP-000391'
  tag fix_id: 'F-26448r461564_fix'
  tag 'documentable'
  tag legacy: ['SV-106501', 'V-97397']
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']
end
