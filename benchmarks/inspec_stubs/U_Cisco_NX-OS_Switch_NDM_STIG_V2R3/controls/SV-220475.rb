control 'SV-220475' do
  title 'The Cisco switch must be configured to automatically audit account creation.'
  desc 'Upon gaining access to a network device, an attacker will often first attempt to create a persistent method of reestablishing access. One way to accomplish this is to create a new account. Notification of account creation helps to mitigate this risk. Auditing account creation provides the necessary reconciliation that account management procedures are being followed. Without this audit trail, personnel without the proper authorization may gain access to critical network nodes.'
  desc 'check', 'Review the switch configuration to determine if it automatically audits account creation. 

Step 1: Verify that account records will be sent to an AAA server as shown in the example below:

aaa accounting default group RADIUS_SERVERS

Step 2: Verify that the referenced group name has defined AAA servers that are online.

aaa group server radius RADIUS_SERVERS 
 server 10.1.48.10 
 server 10.1.48.12

Note: Cisco NX-OS devices report configuration activity to TACACS+ or RADIUS servers in the form of accounting records. Each accounting record contains accounting attribute-value (AV) pairs and is stored on the AAA server.

If account creation is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the switch to log account creation using the following steps:

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
  tag check_id: 'C-22190r539146_chk'
  tag severity: 'medium'
  tag gid: 'V-220475'
  tag rid: 'SV-220475r604141_rule'
  tag stig_id: 'CISC-ND-000090'
  tag gtitle: 'SRG-APP-000026-NDM-000208'
  tag fix_id: 'F-22179r539147_fix'
  tag 'documentable'
  tag legacy: ['SV-110597', 'V-101493']
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
