control 'SV-93371' do
  title 'Tanium public keys of content providers must be validated against documented trusted content providers.'
  desc %q(A Tanium Sensor, also called content, enables an organization to gather real-time inventory, configuration, and compliance data elements from managed computers. Sensors gather specific information from the local device and then write the results to the computer's standard output channel. The Tanium Client captures that output and forwards the results through the platform's unique "ring" architecture for display in the Tanium Console.

The language used for Sensor development is based on the scripting engine available on the largest number of devices under management as well as the scripting experience and background of the people who will be responsible for creating new Sensors. VBScript and PowerShell are examples of common scripting languages used for developing sensors.

Because errors in scripting can and will provide errant feedback at best and will impact functionality of the endpoint to which the content is directed, it is imperative to ensure content is only accepted from trusted sources.)
  desc 'check', 'Note: If only using Tanium provided content and not accepting content from any other content providers, this is "Not Applicable".

Obtain documentation from the Tanium System Administrator that contains the public key validation data.

Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Open an Explorer window.

Navigate to the following folder: Program Files >> Tanium >> Tanium Server >> content_public_keys >> content folder.

Ensure the public keys listed in the content folder are documented.

If a public key, other than the default Tanium public key, resides in the content folder and is not documented, this is a finding.'
  desc 'fix', 'Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Open an Explorer window.

Navigate to the following folder: Program Files >> Tanium >> Tanium Server >> content_public_keys >> content folder.

If a public key, other than the default Tanium public key, resides in the content folder, use a hashing utility (e.g., TaniumFileInfo.exe) to determine the hash of the public key.

Document the owner, the name of the key, and the associated hash of the public key.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78235r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78665'
  tag rid: 'SV-93371r1_rule'
  tag stig_id: 'TANS-SV-000005'
  tag gtitle: 'SRG-APP-000015'
  tag fix_id: 'F-85401r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
