control 'SV-235981' do
  title 'Oracle WebLogic must utilize NSA-approved cryptography when protecting classified compartmentalized data.'
  desc 'Cryptography is only as strong as the encryption modules/algorithms employed to encrypt the data. 

Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. Encryption modules/algorithms are the mathematical procedures used for encrypting data.

NSA has developed Type 1 algorithms for protecting classified information. The Committee on National Security Systems (CNSS) National Information Assurance Glossary (CNSS Instruction No. 4009) defines Type 1 products as:

"Cryptographic equipment, assembly or component classified or certified by NSA for encrypting and decrypting classified and sensitive national security information when appropriately keyed. Developed using established NSA business processes and containing NSA-approved algorithms. Used to protect systems requiring the most stringent protection mechanisms."

Although persons may have a security clearance, they may not have a "need to know" and are required to be separated from the information in question. The application server must employ NSA-approved cryptography to protect classified information from those individuals who have no "need to know" or when encryption of compartmentalized data is required by data classification.'
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
  tag check_id: 'C-39200r628719_chk'
  tag severity: 'medium'
  tag gid: 'V-235981'
  tag rid: 'SV-235981r628721_rule'
  tag stig_id: 'WBLC-08-000214'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-39163r628720_fix'
  tag 'documentable'
  tag legacy: ['SV-70567', 'V-56313']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
