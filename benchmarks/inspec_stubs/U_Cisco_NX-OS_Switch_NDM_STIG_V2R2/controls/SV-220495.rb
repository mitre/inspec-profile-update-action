control 'SV-220495' do
  title 'The Cisco switch must be configured to audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement. The configuration example below will log all configuration changes.

Step 1: Verify that account records will be sent to an AAA server as shown in the example below:

aaa accounting default group RADIUS_SERVERS

Step 2: Verify that the referenced group name has defined AAA servers that are online.

aaa group server radius RADIUS_SERVERS 
 server 10.1.48.10 
 server 10.1.48.12

Note: Cisco NX-OS devices report configuration activity to TACACS+ or RADIUS servers in the form of accounting records. Each accounting record contains accounting attribute-value (AV) pairs and is stored on the AAA server.

If the Cisco switch is not configured to log all configuration changes, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to log all configuration changes as shown in the following example:

Step 1: Configure the AAA servers as shown in the example below:

SW1(config)# radius-server host 10.1.48.10 
SW1(config)# radius-server host 10.1.48.12

Step 2: Configure an AAA server group as shown in the example below:

SW1(config)# aaa group server radius RADIUS_SERVERS
SW1(config-radius)# server 10.1.48.10 
SW1(config-radius)# server 10.1.48.12
SW1(config-radius)# exit

Step 3: Enable AAA accounting as shown in the example below:

SW1(config)# aaa accounting default group RADIUS_SERVERS
SW1(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22210r539206_chk'
  tag severity: 'medium'
  tag gid: 'V-220495'
  tag rid: 'SV-220495r604141_rule'
  tag stig_id: 'CISC-ND-000940'
  tag gtitle: 'SRG-APP-000343-NDM-000289'
  tag fix_id: 'F-22199r539207_fix'
  tag 'documentable'
  tag legacy: ['SV-110639', 'V-101535']
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
