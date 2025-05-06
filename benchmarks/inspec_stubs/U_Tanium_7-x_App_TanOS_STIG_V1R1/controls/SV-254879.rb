control 'SV-254879' do
  title 'Content providers must provide their public key to the Tanium administrator to import for validating signed content.'
  desc %q(A Tanium Sensor, also called content, enables an organization to gather real-time inventory, configuration, and compliance data elements from managed computers. Sensors gather specific information from the local device and then write the results to the computer's standard output channel. The Tanium Client captures that output and forwards the results through the platform's unique "ring" architecture for display in the Tanium Console.

The language used for Sensor development is based on the scripting engine available on the largest number of devices under management as well as the scripting experience and background of the people who will be responsible for creating new Sensors. VBScript and PowerShell are examples of common scripting languages used for developing sensors.

Because errors in scripting can and will provide errant feedback at best and will impact functionality of the endpoint to which the content is directed, it is imperative to ensure content is only accepted from trusted sources.)
  desc 'check', 'Note: If only using Tanium-provided content and not accepting content from any other content providers, this is Not Applicable.  

Obtain documentation from the Tanium System Administrator that contains the public key validation data.  

1. Access the Tanium Server interactively.  

2. Log on to the TanOS server with the tanadmin role.  

3. Press "2" for "Tanium Operations Menu," and then press "Enter".  

4. Press "5" for "Manage Custom Signing Keys," and then press "Enter". 

5. Press "L" for "List Content Signing Keys," and then press "Enter".  

If signing keys not listed in the provided documentation are present, this is a finding.'
  desc 'fix', 'Note: If only using Tanium-provided content and not accepting content from any other content providers, this is Not Applicable.  

Obtain documentation from the Tanium System Administrator that contains the public key validation data.  

1. Access the Tanium Server interactively.  

2. Log on to the TanOS server with the tanadmin role.  

3. Press "2" for "Tanium Operations Menu," and then press "Enter".  

4. Press "5" for "Manage Custom Signing Keys," and then press "Enter".  

5. Press "A" for "List Content Signing Keys," and then press "Enter".  

6. Check the provided documentation and either update the document with the name and SHA-256 hash of the key or remove the key.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58492r867535_chk'
  tag severity: 'medium'
  tag gid: 'V-254879'
  tag rid: 'SV-254879r867537_rule'
  tag stig_id: 'TANS-AP-000050'
  tag gtitle: 'SRG-APP-000015'
  tag fix_id: 'F-58436r867536_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
