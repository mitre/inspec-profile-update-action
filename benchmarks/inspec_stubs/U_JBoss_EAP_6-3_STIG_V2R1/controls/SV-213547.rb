control 'SV-213547' do
  title 'JBoss must be configured to use an approved TLS version.'
  desc 'Preventing the disclosure of transmitted information requires that the application server take measures to employ some form of cryptographic mechanism in order to protect the information during transmission.  This is usually achieved through the use of Transport Layer Security (TLS). 

JBoss relies on the underlying SSL implementation running on the OS.  This can be either Java based or OpenSSL.  The SSL protocol setting determines which SSL protocol is used.  SSL has known security vulnerabilities, so TLS should be used instead. 

If data is transmitted unencrypted, the data then becomes vulnerable to disclosure.  The disclosure may reveal user identifier/password combinations, website code revealing business logic, or other user personal information.

FIPS 140-2 approved TLS versions include TLS V1.2 or greater.

TLS must be enabled, and non-FIPS-approved SSL versions must be disabled.  NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss. 
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder. 
Run the jboss-cli script.  
Connect to the server and authenticate. 

Validate that the TLS protocol is used for HTTPS connections.
Run the command:

"ls /subsystem=web/connector=https/ssl=configuration"

If a TLS V1.2 or higher protocol is not returned, this is a finding.'
  desc 'fix', "Reference section 4.6 of the JBoss EAP 6.3 Security Guide located on the Red Hat vendor's web site for step-by-step instructions on establishing SSL encryption on JBoss.

The overall steps include:

1. Add an HTTPS connector.
2. Configure the SSL encryption certificate and keys.
3. Set the protocol to TLS V1.2 or greater."
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14770r612224_chk'
  tag severity: 'medium'
  tag gid: 'V-213547'
  tag rid: 'SV-213547r615939_rule'
  tag stig_id: 'JBOS-AS-000650'
  tag gtitle: 'SRG-APP-000439-AS-000155'
  tag fix_id: 'F-14768r612225_fix'
  tag 'documentable'
  tag legacy: ['SV-76811', 'V-62321']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
