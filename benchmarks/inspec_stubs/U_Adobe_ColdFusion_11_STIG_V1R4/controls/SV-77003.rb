control 'SV-77003' do
  title 'ColdFusion must employ approved cryptographic mechanisms to prevent unauthorized disclosure of information and/or detect changes to information during transmission.'
  desc 'Preventing the disclosure or modification of transmitted information requires that application servers take measures to employ approved cryptography in order to protect the information during transmission over the network. This is usually achieved through the use of Transport Layer Security (TLS), SSL VPN, or IPSec tunnel.

If data in transit is unencrypted, it is vulnerable to disclosure and modification. If approved cryptographic algorithms are not used, encryption strength cannot be assured.

ColdFusion uses the underlying JVM to handle transmission and receiving of data, but ColdFusion does offer to the programmer an encrypt API call to protect the data.  This call can use multiple crypto methods, but using FIPS 140-2 is superior to those non-FIPS crypto methods to protect and detect changes to the data.  Through JVM arguments set within ColdFusion, the programmer can be forced to only FIPS crypto methods.'
  desc 'check', 'Within the Administrator Console, navigate to the "Java and JVM" page under the "Server Settings" menu.

If the JVM argument-Dcoldfusion.enablefipscrypto=true cannot be found or -Dcoldfusion.enablefipscrypto is set to false, this is a finding.'
  desc 'fix', 'Navigate to the "Java and JVM" page under the "Server Settings" menu.  Locate the JVM argument coldfusion.enablefipscrypto.  If the argument cannot be found, add the argument as -Dcoldfusion.enablefipscrypto=true.  If the parameter is defined but set to false, change the setting to true.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63317r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62513'
  tag rid: 'SV-77003r1_rule'
  tag stig_id: 'CF11-05-000197'
  tag gtitle: 'SRG-APP-000440-AS-000167'
  tag fix_id: 'F-68433r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
