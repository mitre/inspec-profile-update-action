control 'SV-221429' do
  title 'The WLST_PROPERTIES environment variable defined for the Fusion Middleware WebLogic Scripting Tool must be updated to reference an appropriate trust store so that it can communicate with the Node Manager supporting OHS.'
  desc 'Oracle Node Manager is the utility that is used to perform common operational tasks for OHS.

When starting an OHS instance, the "Fusion Middleware" WebLogic Scripting Tool needs to trust the certificate presented by the Node Manager in order to setup secure communication with it.  If the "Fusion Middleware" WLST does not trust the certificate presented by Node Manager, the "Fusion Middleware" WebLogic Scripting tool will not be able to setup a secure connection to it.'
  desc 'check', '1. Check for the existence of $ORACLE_HOME/oracle_common/common/bin/setWlstEnv.sh.

2a. If the setWlstEnv.sh does not exist or does not contain the "WLST_PROPERTIES" environment variable set to a valid trust keystore containing the Certificate Authority and Chain of the Node Manager identity, this is a finding.
2b. If the setWlstenv.sh file does not exist, this is a finding.
2c. If the setWlstenv.sh file has permissions more permissive than 750, this is a finding.'
  desc 'fix', %q(1. Open $ORACLE_HOME/oracle_common/common/bin/setWlstEnv.sh. with an editor.  If the file does not exist, create the file.

2. Set "WLST_PROPERTIES" environment variable to a valid trust keystore containing the Certificate Authority and Chain of Node Manager identity, add the property if it does not exist.

3. Issue a "chmod 750 $ORACLE_HOME/oracle_common/common/bin/setWlstEnv.sh' to modify the permissions of the script.)
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23144r414970_chk'
  tag severity: 'medium'
  tag gid: 'V-221429'
  tag rid: 'SV-221429r414972_rule'
  tag stig_id: 'OH12-1X-000190'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23133r414971_fix'
  tag 'documentable'
  tag legacy: ['SV-79109', 'V-64619']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
