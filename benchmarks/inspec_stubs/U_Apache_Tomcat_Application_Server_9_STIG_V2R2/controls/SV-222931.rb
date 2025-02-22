control 'SV-222931' do
  title 'Default password for keystore must be changed.'
  desc %q(Tomcat currently operates only on JKS, PKCS11, or PKCS12 format keystores. The JKS format is Java's standard "Java KeyStore" format, and is the format created by the keytool command-line utility which is included in the JDK. The PKCS12 format is an internet standard, and is managed using OpenSSL or Microsoft's Key-Manager. This requirement only applies to JKS keystores. When a new JKS keystore is created, if a password is not specified during creation the default password used by Tomcat is "changeit" (all lower case). If the default password is not changed, the keystore is at risk of compromise.

)
  desc 'check', 'From the Tomcat server console, run the following command to check the keystore:

sudo keytool -list -v 

When prompted for the keystore password type "changeit" sans quotes.

If the contents of the keystore are displayed, this is a finding.'
  desc 'fix', 'From the Tomcat server as a privileged user, run the following command:

sudo keytool -storepasswd 

When prompted for the keystore password, select a strong password, minimum 10 characters, mixed case alpha-numeric.

Document the password and store in a secured location that is only accessible to authorized personnel.'
  impact 0.7
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24603r426237_chk'
  tag severity: 'high'
  tag gid: 'V-222931'
  tag rid: 'SV-222931r615938_rule'
  tag stig_id: 'TCAT-AS-000060'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-24592r426238_fix'
  tag satisfies: ['SRG-APP-000033-AS-000023', 'SRG-APP-000176-AS-000125']
  tag 'documentable'
  tag legacy: ['SV-111393', 'V-102445']
  tag cci: ['CCI-000186', 'CCI-000213']
  tag nist: ['IA-5 (2) (a) (1)', 'AC-3']
end
