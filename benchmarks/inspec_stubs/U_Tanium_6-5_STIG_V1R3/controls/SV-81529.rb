control 'SV-81529' do
  title 'Trusted Content providers must be documented.'
  desc %q(A Tanium Sensor, also called content, enables an organization to gather real-time inventory, configuration, and compliance data elements from managed computers. Sensors gather specific information from the local device and then write the results to the computer's standard output channel. The Tanium Client captures that output and forwards the results through the platform's unique "ring" architecture for display in the Tanium Console. 

The language used for Sensor development is based on the scripting engine available on the largest number of devices under management as well as the scripting experience and background of the people who will be responsible for creating new Sensors. VBScript and PowerShell are examples of common scripting languages used for developing sensors.

Because errors in scripting can and will provide errant feedback at best and will impact functionality of the endpoint to which the content is directed, it is imperative to ensure content is only accepted from trusted sources.)
  desc 'check', 'Note: If only using Tanium provided content and not accepting content from any other content providers, this is Not Applicable.

Consult with the Tanium System Administrator to review the documented list of trusted content providers along with the HASH for their respective public keys. 

If the site does not have the Tanium trusted content providers documented along with the HASH for their respective public keys, this is a finding.'
  desc 'fix', 'Prepare and maintain documentation identifying the Tanium trusted content providers along with the HASH from their respective public keys.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67675r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67039'
  tag rid: 'SV-81529r1_rule'
  tag stig_id: 'TANS-SV-000003'
  tag gtitle: 'SRG-APP-000015'
  tag fix_id: 'F-73139r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
