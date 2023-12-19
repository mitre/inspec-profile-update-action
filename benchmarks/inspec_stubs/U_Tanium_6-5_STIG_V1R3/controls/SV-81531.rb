control 'SV-81531' do
  title 'Content providers must provide their public key to the Tanium administrator to import for validating signed content.'
  desc %q(A Tanium Sensor, also called content, enables an organization to gather real-time inventory, configuration, and compliance data elements from managed computers. Sensors gather specific information from the local device and then write the results to the computer's standard output channel. The Tanium Client captures that output and forwards the results through the platform's unique "ring" architecture for display in the Tanium Console. 

The language used for Sensor development is based on the scripting engine available on the largest number of devices under management as well as the scripting experience and background of the people who will be responsible for creating new Sensors. VBScript and PowerShell are examples of common scripting languages used for developing sensors.

Because errors in scripting can and will provide errant feedback at best and will impact functionality of the endpoint to which the content is directed, it is imperative to ensure content is only accepted from trusted sources.)
  desc 'check', 'Note: If only using Tanium provided content and not accepting content from any other content providers, this is Not Applicable.

Access the Tanium Server interactively. Log on with an account with administrative privileges to the server.

Open an Explorer window. 

Navigate to the \\Program Files\\Tanium\\Tanium Server\\content_public_keys\\content folder.

If the Tanium default content-release.pub key is the only key in the folder, and there are content providers other than Tanium, this is a finding.'
  desc 'fix', %q(Obtain .XML content from trusted provider, including their public key. If trusted provider can't provide their signed content along with their public key, remove their respective content from the Tanium Server and from the trusted provider list until it can be provided.

Access the Tanium Server interactively. Log on with an account with administrative privileges to the server.

Open an Explorer window. 

Navigate to the \Program Files\Tanium\Tanium Server\content_public_keys\content folder. 

Copy Trusted Source's .pub key into the folder.

Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and logon with CAC. 

From the console's “Authoring” tab, click the "Import From XML" link in the upper right corner. 

Browse to the signed xml file and select it. If a “Content Import Review” screen is displayed, verify content being imported is the most recent content from this provider and select “Overwrite database duplicates”.)
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67677r2_chk'
  tag severity: 'medium'
  tag gid: 'V-67041'
  tag rid: 'SV-81531r1_rule'
  tag stig_id: 'TANS-SV-000004'
  tag gtitle: 'SRG-APP-000015'
  tag fix_id: 'F-73141r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
