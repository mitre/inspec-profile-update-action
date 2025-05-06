control 'SV-77011' do
  title 'ColdFusion must use DoD- or CNSS-approved PKI Class 3 or Class 4 certificates.'
  desc 'Class 3 PKI certificates are used for servers and software signing rather than for identifying individuals. Class 4 certificates are used for business-to-business transactions. Utilizing unapproved certificates not issued or approved by DoD or CNS creates an integrity risk. The application server must utilize approved DoD or CNS Class 3 or Class 4 certificates for software signing and business-to-business transactions.

ColdFusion uses an underlying JVM for communication and certificate storage.  To validate that the proper certificates are in use, the keystore must be checked.'
  desc 'check', 'Interview the administrator to determine if ColdFusion is using certificates for PKI.  If ColdFusion is not performing any PKI functions, this finding is not applicable.

The CA certs are usually stored in a file called cacerts located in the directory $JAVA_HOME/jre/lib/security.  If the file is not in this location, use a search command to locate the file or ask the administrator where the certificate store is located.

Open a dos shell or terminal window and change to the location of the certificate store.  To view the certificates within the certificate store, run the command (In this example, the keystore file is cacerts.): keytool -list -v -keystore cacerts

Locate the "OU" field for each certificate within the keystore.  The field should contain either DoD or CNSS as the Organizational Unit (OU).

If the OU does not show that the certificates are DoD or CNSS supplied, this is a finding.'
  desc 'fix', 'Request a CNSS or DoD Class 3 or Class 4 certificate and add it to the keystore to be used for PKI communication.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63325r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62521'
  tag rid: 'SV-77011r1_rule'
  tag stig_id: 'CF11-05-000203'
  tag gtitle: 'SRG-APP-000514-AS-000137'
  tag fix_id: 'F-68441r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
