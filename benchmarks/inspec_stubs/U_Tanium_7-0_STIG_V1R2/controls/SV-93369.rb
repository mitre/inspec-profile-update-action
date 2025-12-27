control 'SV-93369' do
  title 'Content providers must provide their public key to the Tanium administrator to import for validating signed content.'
  desc %q(A Tanium Sensor, also called content, enables an organization to gather real-time inventory, configuration, and compliance data elements from managed computers. Sensors gather specific information from the local device and then write the results to the computer's standard output channel. The Tanium Client captures that output and forwards the results through the platform's unique "ring" architecture for display in the Tanium Console.

The language used for Sensor development is based on the scripting engine available on the largest number of devices under management as well as the scripting experience and background of the people who will be responsible for creating new Sensors. VBScript and PowerShell are examples of common scripting languages used for developing sensors.

Because errors in scripting can and will provide errant feedback at best and will impact functionality of the endpoint to which the content is directed, it is imperative to ensure content is only accepted from trusted sources.)
  desc 'check', 'Note: If only using Tanium provided content and not accepting content from any other content providers, this is "Not Applicable".

Obtain documentation from the Tanium System Administrator that contains the public key validation data.

Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Open an Explorer window.

Navigate to the following folder: Program Files >> Tanium >> Tanium Server >> content_public_keys >> content folder.

If the Tanium default content-release.pub key is the only key in the folder, this is not a finding.

If there are documented content provider keys in the content folder, this is not a finding.

If non-documented content provider keys are found in the content folder, this is a finding.'
  desc 'fix', "Obtain the public key from the content providers and validate the keys are present in the Tanium folders. If the public keys are found for non-trusted content providers, remove the associated signing key and remove any content imported by that provider.

Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Open an Explorer window.

Navigate to the following folder: Program Files >> Tanium >> Tanium Server >> content_public_keys >> content folder.

Copy any Trusted Source's .pub key into the folder and document them.

Remove any non-Trusted Source's .pub keys from the folder."
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78233r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78663'
  tag rid: 'SV-93369r1_rule'
  tag stig_id: 'TANS-SV-000004'
  tag gtitle: 'SRG-APP-000015'
  tag fix_id: 'F-85399r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
