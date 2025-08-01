control 'SV-76999' do
  title 'ColdFusion must protect the confidentiality and integrity of transmitted information through the use of an approved TLS version.'
  desc 'Preventing the disclosure of transmitted information requires that the application server take measures to employ some form of cryptographic mechanism in order to protect the information during transmission.  This is usually achieved through the use of Transport Layer Security (TLS), but care must also be taken to safeguard against non-FIPS approved SSL versions being used.  These older versions contain vulnerabilities that have been addressed in the newer FIPS 140-2 approved TLS releases.

FIPS 140-2 approved TLS versions include TLS V1.0 or greater.

TLS must be enabled, and non-FIPS-approved SSL versions must be disabled.  NIST SP 800-52 specifies the preferred configurations for government systems.

ColdFusion uses JVM to control the encryption of transmitted data.  Settings for JVM can be controlled within the Administrator Console to configure the JVM to only use FIPS 140-2 approved TLS and disable non-FIPS SSL versions.'
  desc 'check', 'Review the setting "JVM arguments" within the Administrator Console.  These arguments can be found in the "Java and JVM" page accessed through the "Server Settings" menu option.  The parameter -Dhttps.protocols is used to set the TLS versions that the JVM can use.  Valid values for this setting must be TLS versions 1.0 or higher.  An example settings to use TLS versions 1.2, 1.1 and 1.0 is -Dhttps.protocols=TLSv1.2,TLSv1.1,TLSv1 and an example to only use TLS version 1.2 is -Dhttps.protocols=TLSv1.2

If the "JVM arguments" setting does not contain the parameter -Dhttps.protocols or if the parameter -Dhttps.protocols contains any SSL versions, this is a finding.'
  desc 'fix', 'Navigate to the "JVM arguments" setting within the Administrator Console.  These arguments can be found in the "Java and JVM" page accessed through the "Server Settings" menu option.  Add the parameter -Dhttps.protocols and set the parameter to the TLS versions to be used.  A sample setting to use TLSv1.2, TLSv1.1 and TLSv1 is -Dhttps.protocols=TLSv1.2,TLSv1.1,TLSv1.  SSL versions must not be added to this parameter.  Once the parameter is added to the JVM arguments, select the "Submit Changes" button to save the changes and restart the ColdFusion application server to have the changes take effect.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63313r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62509'
  tag rid: 'SV-76999r1_rule'
  tag stig_id: 'CF11-05-000195'
  tag gtitle: 'SRG-APP-000439-AS-000155'
  tag fix_id: 'F-68429r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
