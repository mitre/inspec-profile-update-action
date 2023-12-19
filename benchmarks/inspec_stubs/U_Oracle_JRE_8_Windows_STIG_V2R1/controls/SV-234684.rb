control 'SV-234684' do
  title 'Oracle JRE 8 deployment.config file must contain proper keys and values.'
  desc 'The deployment.config  configuration file contains two keys.  

The "deployment.properties" key includes the path of the "deployment.properties" file and the "deployment.properties.mandatory" key contains either a TRUE or FALSE value.  
 
If the path specified to "deployment.properties" does not lead to a "deployment.properties" file, the value of the “deployment.system.config.mandatory” key determines how JRE will handle the situation.  

If the value of the "deployment.system.config.mandatory" key is TRUE and if the path to the "deployment.properties" file is invalid, the JRE will not allow Java applications to run.   This is the desired behavior.'
  desc 'check', 'Navigate to the "deployment.config" file for Java:

<Windows Directory>\\Sun\\Java\\Deployment\\deployment.config
- or -
<JRE Installation Directory>\\Lib\\deployment.config

The "deployment.config" file contains two properties: deployment.system.config and deployment.system.config.mandatory.

The "deployment.system.config" key points to the location of the "deployment.properties" file. The location is variable. It can point to a file on the local disk or a UNC path. The following is an example:
"deployment.system.config=file:///C:/Windows/Java/Deployment/deployment.properties"

If the "deployment.system.config" key does not exist or does not point to the location of the "deployment.properties" file, this is a finding.

If the "deployment.system.config.mandatory" key does not exist or is set to "false", this is a finding.'
  desc 'fix', 'Navigate to the "deployment.config" file for JRE.

Add the key "deployment.system.config=<Path to deployment.properties>" to the "deployment.config" file. The following is an example:
"deployment.system.config=file:///C:/Windows/Java/Deployment/deployment.properties". Note the use of forward slashes.

Add the key "deployment.system.config.mandatory=true" to the "deployment.config" file.'
  impact 0.5
  ref 'DPMS Target Oracle Java Runtime Environment v8 for Windows'
  tag check_id: 'C-37869r616108_chk'
  tag severity: 'medium'
  tag gid: 'V-234684'
  tag rid: 'SV-234684r617446_rule'
  tag stig_id: 'JRE8-WN-000020'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-37834r616109_fix'
  tag 'documentable'
  tag legacy: ['V-66941', 'SV-81431']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
