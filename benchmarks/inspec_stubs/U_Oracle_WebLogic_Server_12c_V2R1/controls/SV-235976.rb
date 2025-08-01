control 'SV-235976' do
  title 'Oracle WebLogic must utilize FIPS 140-2 approved encryption modules when authenticating users and processes.'
  desc 'Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms. 

FIPS 140-2 is the current standard for validating cryptographic modules, and NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified hardware-based encryption modules. 

Application servers must provide FIPS-compliant encryption modules when authenticating users and processes.'
  desc 'check', %q(1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for 'AdminServer' target
5. From the list of log files, select 'AdminServer.log' and click 'View Log File' button
6. Within the search criteria, enter the value 'FIPS' for the 'Message contains' field, and select the appropriate 'Start Date' and 'End Date' range. Click 'Search'
7. Check for the following log entry: "Changing the default Random Number Generator in RSA CryptoJ ... to FIPS186PRNG" or "Changing the default Random Number Generator in RSA CryptoJ from ECDRBG128 to HMACDRBG."

If either of these log entries are found, this is not a finding.

If a log entry cannot be found, navigate to the DOMAIN_HOME directory: 
8. View the contents of the appropriate WebLogic server start script:
On UNIX operating systems: startWebLogic.sh
On Microsoft Windows operating systems: startWebLogic.cmd
9. Ensure the JAVA_OPTIONS variable is set:
On UNIX operating systems: 
JAVA_OPTIONS=" -Djava.security.properties==/<mylocation>/java.security ${JAVA_OPTIONS}"
On Microsoft Windows operating systems: 
set JAVA_OPTIONS= -Djava.security.properties==C:\<mylocation>\java.security %JAVA_OPTIONS%
10. Ensure the <mylocation> path specified above contains a valid java.security file (Refer to section 2.2.4 of the Overview document)
11. Ensure the PRE_CLASSPATH variable is set:
On UNIX operating systems: 
PRE_CLASSPATH="%MW_HOME%\wlserver\server\lib\jcmFIPS.jar;%MW_HOME%\wlserver\server\lib\sslj.jar ${PRE_CLASSPATH}"
On Microsoft Windows operating systems: 
set PRE_CLASSPATH= %MW_HOME%\wlserver\server\lib\jcmFIPS.jar;%MW_HOME%\wlserver\server\lib\sslj.jar;%PRE_CLASSPATH%

If the java options are not set correctly, this is a finding.)
  desc 'fix', '1. Shut down any running instances of WebLogic server
2. On disk, navigate to the DOMAIN_HOME directory 
3. View the contents of the appropriate WebLogic server start script:
On UNIX operating systems: startWebLogic.sh
On Microsoft Windows operating systems: startWebLogic.cmd
4. Ensure the JAVA_OPTIONS variable is set:
On UNIX operating systems: 
JAVA_OPTIONS=" -Djava.security.properties==/<mylocation>/java.security ${JAVA_OPTIONS}"
On Microsoft Windows operating systems: 
set JAVA_OPTIONS= -Djava.security.properties==C:\\<mylocation>\\java.security %JAVA_OPTIONS%
5. Ensure the <mylocation> path specified above contains a valid java.security file (Refer to section 2.2.4 of the Overview document)
6. Ensure the PRE_CLASSPATH variable is set:
On UNIX operating systems: 
PRE_CLASSPATH="%MW_HOME%\\wlserver\\server\\lib\\jcmFIPS.jar;%MW_HOME%\\wlserver\\server\\lib\\sslj.jar ${PRE_CLASSPATH}"
On Microsoft Windows operating systems: 
set PRE_CLASSPATH= %MW_HOME%\\wlserver\\server\\lib\\jcmFIPS.jar;%MW_HOME%\\wlserver\\server\\lib\\sslj.jar;%PRE_CLASSPATH%
7. Refer to section 2.2.4 of the Overview document'
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39195r628704_chk'
  tag severity: 'medium'
  tag gid: 'V-235976'
  tag rid: 'SV-235976r628706_rule'
  tag stig_id: 'WBLC-05-000177'
  tag gtitle: 'SRG-APP-000179-AS-000129'
  tag fix_id: 'F-39158r628705_fix'
  tag 'documentable'
  tag legacy: ['SV-70555', 'V-56301']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
