control 'SV-234685' do
  title 'Oracle JRE 8 must have a deployment.properties file present.'
  desc 'By default no deployment.properties file exists; thus, no system-wide deployment exists. The file must be created. The deployment.properties file is used for specifying keys for the Java Runtime Environment.  Each option in the Java control panel is represented by property keys. These keys adjust the options in the Java control panel based on the value assigned to that key.  Without the deployment.properties file, setting particular options for the Java control panel is impossible.'
  desc 'check', 'Navigate to the system-level "deployment.properties" file for JRE.

The location of the "deployment.properties" file is defined in the "deployment.config" file.

If there are no files titled "deployment.properties", this is a finding.'
  desc 'fix', 'Create the JRE "deployment.properties" file:

No default file exists. A text file named "deployment.properties", and the directory structure in which it is located, must be manually created.
The location must be aligned as defined in the "deployment.config" file.

C:\\Windows\\Java\\Deployment\\deployment.properties is an example.'
  impact 0.5
  ref 'DPMS Target Oracle Java Runtime Environment v8 for Windows'
  tag check_id: 'C-37870r616111_chk'
  tag severity: 'medium'
  tag gid: 'V-234685'
  tag rid: 'SV-234685r617446_rule'
  tag stig_id: 'JRE8-WN-000030'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-37835r616112_fix'
  tag 'documentable'
  tag legacy: ['V-66943', 'SV-81433']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
