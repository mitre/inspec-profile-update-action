control 'SV-253840' do
  title 'Tanium public keys of content providers must be validated against documented trusted content providers.'
  desc %q(A Tanium Sensor, also called content, enables an organization to gather real-time inventory, configuration, and compliance data elements from managed computers. Sensors gather specific information from the local device and then write the results to the computer's standard output channel. The Tanium Client captures that output and forwards the results through the platform's unique "ring" architecture for display in the Tanium Console.

The language used for Sensor development is based on the scripting engine available on the largest number of devices under management as well as the scripting experience and background of the people who will be responsible for creating new Sensors. VBScript and PowerShell are examples of common scripting languages used for developing sensors.

Because errors in scripting can and will provide errant feedback at best and will impact functionality of the endpoint to which the content is directed, it is imperative to ensure content is only accepted from trusted sources.)
  desc 'check', 'Note: If only using Tanium-provided content and not accepting content from any other content providers, this is not applicable.

Obtain documentation from the Tanium system administrator that contains the public key validation data.

1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Open an Explorer window.

4. Navigate to the following folder: Program Files >> Tanium >> Tanium Server >> content_public_keys >> content folder.

5. Verify the public keys listed in the content folder are documented.

If a public key, other than the default Tanium public key, is in the content folder and is not documented, this is a finding.'
  desc 'fix', '1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Open an Explorer window.

4. Navigate to the following folder: Program Files >> Tanium >> Tanium Server >> content_public_keys >> content folder.

5. If a public key, other than the default Tanium public key, resides in the content folder, use a hashing utility (e.g., TaniumFileInfo.exe) to determine the hash of the public key.

6. Document the owner, the name of the key, and the associated hash of the public key.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57292r842546_chk'
  tag severity: 'medium'
  tag gid: 'V-253840'
  tag rid: 'SV-253840r842548_rule'
  tag stig_id: 'TANS-SV-000005'
  tag gtitle: 'SRG-APP-000015'
  tag fix_id: 'F-57243r842547_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
