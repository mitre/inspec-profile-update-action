control 'SV-213495' do
  title 'HTTPS must be enabled for JBoss web interfaces.'
  desc "Encryption is critical for protection of web-based traffic. If encryption is not being used to protect the application server's web connectors, malicious users may gain the ability to read or modify the application traffic while it is in transit over the network. The use of cryptography on web connectors secures web-based traffic and mitigates that risk. HTTPS and Transport Layer Security (TLS) are the means in which cryptographic protections are applied to web connectors.

FIPS 140-2 approved TLS versions include TLS V1.2 or greater."
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.
 
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder. 
Run the jboss-cli script. 
Connect to the server and authenticate. 

Review the web subsystem and ensure that HTTPS is enabled.
Run the command:

For a managed domain:
"ls /profile=<PROFILE_NAME>/subsystem=web/connector="

For a standalone system:
"ls /subsystem=web/connector="

If "https" is not returned, this is a finding.'
  desc 'fix', %q(Follow procedure "4.4.  Configure the JBoss Web Server to use HTTPS."  The detailed procedure is found in the JBoss EAP 6.3 Security Guide available at the vendor's site, RedHat.com.  An overview of steps is provided here.

1. Obtain or generate DoD-approved SSL certificates.
2. Configure the SSL certificate using your certificate values.
3. Set the SSL protocol to TLS V1.2 or greater.)
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14718r296151_chk'
  tag severity: 'medium'
  tag gid: 'V-213495'
  tag rid: 'SV-213495r809511_rule'
  tag stig_id: 'JBOS-AS-000015'
  tag gtitle: 'SRG-APP-000015-AS-000010'
  tag fix_id: 'F-14716r622479_fix'
  tag 'documentable'
  tag legacy: ['SV-76705', 'V-62215']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
