control 'SV-220482' do
  title 'The Cisco switch must be configured to protect against an individual falsely denying having performed organization-defined actions to be covered by non-repudiation.'
  desc 'This requirement supports non-repudiation of actions taken by an administrator and is required in order to maintain the integrity of the configuration management process. All configuration changes to the network device are logged, and administrators authenticate with two-factor authentication before gaining administrative access. Together, these processes will ensure the administrators can be held accountable for the configuration changes they implement.

To meet this requirement, the network device must log administrator access and activity.'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement as shown in steps below:

Step 1: Verify that account records will be sent to an AAA server as shown in the example below:

aaa accounting default group RADIUS_SERVERS

Step 2: Verify that the referenced group name has defined AAA servers that are online.

aaa group server radius RADIUS_SERVERS 
 server 10.1.48.10 
 server 10.1.48.12

Note: Cisco NX-OS devices report configuration activity to TACACS+ or RADIUS servers in the form of accounting records. Each accounting record contains accounting attribute-value (AV) pairs and is stored on the AAA server.

If logging of administrator activity is not configured, this is a finding.'
  desc 'fix', 'Configure the switch to log administrator activity as shown in the steps below:

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
  tag check_id: 'C-22197r539167_chk'
  tag severity: 'medium'
  tag gid: 'V-220482'
  tag rid: 'SV-220482r879554_rule'
  tag stig_id: 'CISC-ND-000210'
  tag gtitle: 'SRG-APP-000080-NDM-000220'
  tag fix_id: 'F-22186r539168_fix'
  tag 'documentable'
  tag legacy: ['SV-110611', 'V-101507']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
