control 'SV-220507' do
  title 'The Cisco switch must be configured to generate log records when administrator privileges are deleted.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement as shown in the example below:

Step 1: Verify that account records will be sent to an AAA server as shown in the example below:

aaa accounting default group RADIUS_SERVERS

Step 2: Verify that the referenced group name has defined AAA servers that are online.

aaa group server radius RADIUS_SERVERS 
 server 10.1.48.10 
 server 10.1.48.12

Note: Cisco NX-OS devices report configuration activity to TACACS+ or RADIUS servers in the form of accounting records. Each accounting record contains accounting attribute-value (AV) pairs and is stored on the AAA server.

If the Cisco switch is not configured to generate log records when administrator privileges are deleted, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to generate log records when administrator privileges are deleted as shown in the example below:

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
  tag check_id: 'C-22222r539242_chk'
  tag severity: 'medium'
  tag gid: 'V-220507'
  tag rid: 'SV-220507r604141_rule'
  tag stig_id: 'CISC-ND-001250'
  tag gtitle: 'SRG-APP-000499-NDM-000319'
  tag fix_id: 'F-22211r539243_fix'
  tag 'documentable'
  tag legacy: ['SV-110663', 'V-101559']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
