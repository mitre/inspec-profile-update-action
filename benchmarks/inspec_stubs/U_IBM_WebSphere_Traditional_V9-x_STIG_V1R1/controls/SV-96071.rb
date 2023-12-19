control 'SV-96071' do
  title 'The WebSphere Application Server default keystore passwords must be changed.'
  desc 'The cornerstone of the PKI is the private key used to encrypt or digitally sign information. 

If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and can pretend to be the authorized user. 

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys. Java-based application servers utilize the Java keystore, which provides storage for cryptographic keys and certificates. The keystore is usually maintained in a file stored on the file system.'
  desc 'check', 'Review System Security Plan documentation.

Interview the system administrator.

Identify installation folders and DMGR info.

Access the DMGR system via the OS.

Stop the DMGR processes. This will shut down the application server so plan outages accordingly. 

The default file paths and DefaultMgr installation names are provided below, adjust paths, and dmgr name if your installation differs from the default.

For UNIX systems:
cd /opt/IBM/Websphere/Profiles/<DefaultDmgr01>/logs/dmgr/

-stopManager.sh -user [admin user name] - password [admin user password]
-archive the SystemOut*.log files. (Copy to another location)
-startManager.sh
-grep -i cwpki0041w SystemOut.log

For Windows:
cd C:\\program files\\IBM\\Websphere\\Profiles\\<DefaultDmgr01>\\logs\\dmgr\\

-stopManager.exe -user [admin user name] - password [admin user password]
-archive the SystemOut*.log files. (Copy to another location)
-startManager.exe
-findstr -I cwpki0041w systemout.log

If the results include: 
"CWPKI0041W: One or more keystores are using the default password", this is a finding.'
  desc 'fix', 'Navigate to Security >> SSL Certificate and Key Management >> Key stores and certificates.

Select a keystore from the list.

Click "Change Password".

Enter the new password and password confirmation.

Click "OK".

Repeat for every keystore in the list.

Synchronize changes to all nodes.'
  impact 0.7
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81063r2_chk'
  tag severity: 'high'
  tag gid: 'V-81357'
  tag rid: 'SV-96071r1_rule'
  tag stig_id: 'WBSP-AS-001230'
  tag gtitle: 'SRG-APP-000176-AS-000125'
  tag fix_id: 'F-88143r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
