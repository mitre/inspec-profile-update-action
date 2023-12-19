control 'SV-221518' do
  title 'OHS must use wallets that have only DoD certificate authorities defined.'
  desc 'Non-DoD approved PKIs have not been evaluated to ensure that they have security controls and identity vetting procedures in place which are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.'
  desc 'check', '1. Go to the location of the OHS keystores (e.g., cd $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/keystores).

2. For each wallet directory located there, do the following:

a) Issue the command "$ORACLE_HOME/oracle_common/bin/orapki wallet display -wallet <wallet_directory>".
b) Confirm that only the appropriate DoD Certificate Authorities are listed as Trusted Certificates.

3. If any of the Trusted Certificates are not appropriate DoD Certificate Authorities, this is a finding.'
  desc 'fix', '1. Go to the location of the OHS keystores (e.g., cd $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/keystores).

2. For each wallet directory located there, do the following:

a) Issue the command "$ORACLE_HOME/oracle_common/bin/orapki wallet display -wallet <wallet_directory>".
b) Remove each Trusted Certificate from the wallet that is not an appropriate DoD Certificate Authority with the command "$ORACLE_HOME/oracle_common/bin/orapki wallet remove -wallet <wallet_directory> -dn <dn_of_the_trusted_certificate> -trusted_cert".'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23233r415233_chk'
  tag severity: 'medium'
  tag gid: 'V-221518'
  tag rid: 'SV-221518r879798_rule'
  tag stig_id: 'OH12-1X-000303'
  tag gtitle: 'SRG-APP-000427-WSR-000186'
  tag fix_id: 'F-23222r415234_fix'
  tag 'documentable'
  tag legacy: ['SV-79017', 'V-64527']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
