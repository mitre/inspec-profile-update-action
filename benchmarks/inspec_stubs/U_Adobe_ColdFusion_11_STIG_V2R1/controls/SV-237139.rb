control 'SV-237139' do
  title 'ColdFusion must implement cryptography mechanisms to protect the integrity of the remote access session.'
  desc 'Protecting the data by not allowing unsecure non-FIPS 140-2 modules to be used and forcing FIPS 140-2 approved encryption modules limits the attack vector for an attacker.  Several attacks, such as the POODLE attack and variants of the POODLE attack, take advantage of forcing an https communication to back down to an unsecure encryption module allowing the attacker to then read the encrypted data.'
  desc 'check', 'Review the setting "JVM arguments" within the Administrator Console.  These arguments can be found in the "Java and JVM" page accessed through the "Server Settings" menu option.  The parameter -Dhttps.protocols is used to set the TLS versions that the JVM can use.  Valid values for this setting must be TLS versions 1.0 or higher.  An example setting to use TLS versions 1.2, 1.1 and 1.0 is -Dhttps.protocols=TLSv1.2,TLSv1.1,TLSv1 and an example to only use TLS version 1.2 is -Dhttps.protocols=TLSv1.2

If the "JVM arguments" setting does not contain the parameter -Dhttps.protocols or if the parameter -Dhttps.protocols contains any SSL versions, this is a finding.'
  desc 'fix', 'Navigate to the "JVM arguments" setting within the Administrator Console.  These arguments can be found in the "Java and JVM" page accessed through the "Server Settings" menu option.  Add the parameter -Dhttps.protocols and set the parameter to the TLS versions to be used.  A sample setting to use TLSv1.2, TLSv1.1 and TLSv1 is - Dhttps.protocols=TLSv1.2,TLSv1.1,TLSv1.  SSL versions must not be added to this parameter.  Once the parameter is added to the JVM arguments, select the "Submit Changes" button to save the changes and restart the ColdFusion application server to have the changes take effect.'
  impact 0.7
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40358r641510_chk'
  tag severity: 'high'
  tag gid: 'V-237139'
  tag rid: 'SV-237139r641512_rule'
  tag stig_id: 'CF11-01-000005'
  tag gtitle: 'SRG-APP-000015-AS-000010'
  tag fix_id: 'F-40321r641511_fix'
  tag 'documentable'
  tag legacy: ['SV-76841', 'V-62351']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
