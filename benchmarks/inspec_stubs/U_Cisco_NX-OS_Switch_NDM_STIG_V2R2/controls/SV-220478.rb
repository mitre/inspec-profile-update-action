control 'SV-220478' do
  title 'The Cisco switch must be configured to automatically audit account removal actions.'
  desc 'Account management, as a whole, ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel. Auditing account removal actions will support account management procedures. When device management accounts are terminated, user or service accessibility may be affected. Auditing also ensures authorized active accounts remain enabled and available for use when required.'
  desc 'check', 'Review the switch configuration to determine if it automatically audits account removal. 

Step 1: Verify that account records will be sent to an AAA server as shown in the example below:

aaa accounting default group RADIUS_SERVERS

Step 2: Verify that the referenced group name has defined AAA servers that are online.

aaa group server radius RADIUS_SERVERS 
 server 10.1.48.10 
 server 10.1.48.12

Note: Cisco NX-OS devices report configuration activity to TACACS+ or RADIUS servers in the form of accounting records. Each accounting record contains accounting attribute-value (AV) pairs and is stored on the AAA server.

If account removal is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the switch to log account removal using the following steps:

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
  tag check_id: 'C-22193r539155_chk'
  tag severity: 'medium'
  tag gid: 'V-220478'
  tag rid: 'SV-220478r604141_rule'
  tag stig_id: 'CISC-ND-000120'
  tag gtitle: 'SRG-APP-000029-NDM-000211'
  tag fix_id: 'F-22182r539156_fix'
  tag 'documentable'
  tag legacy: ['SV-110603', 'V-101499']
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
