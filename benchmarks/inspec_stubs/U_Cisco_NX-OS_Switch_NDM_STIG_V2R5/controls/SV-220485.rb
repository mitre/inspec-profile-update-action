control 'SV-220485' do
  title 'The Cisco switch must be configured to generate audit records containing the full-text recording of privileged commands.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. 

Organizations consider limiting the additional audit information to only that information explicitly needed for specific audit requirements. The additional information required is dependent on the type of information (i.e., sensitivity of the data and the environment within which it resides). At a minimum, the organization must audit full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement. 

Step 1: Verify that account records will be sent to an AAA server as shown in the example below:

aaa accounting default group RADIUS_SERVERS

Step 2: Verify that the referenced group name has defined AAA servers that are online.

aaa group server radius RADIUS_SERVERS 
 server 10.1.48.10 
 server 10.1.48.12

Note: Cisco NX-OS devices report configuration activity to TACACS+ or RADIUS servers in the form of accounting records. Each accounting record contains accounting attribute-value (AV) pairs and is stored on the AAA server.

If the Cisco switch is not configured to generate audit records of configuration changes, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to log all configuration changes as shown in the example below:

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
  tag check_id: 'C-22200r539176_chk'
  tag severity: 'medium'
  tag gid: 'V-220485'
  tag rid: 'SV-220485r879569_rule'
  tag stig_id: 'CISC-ND-000330'
  tag gtitle: 'SRG-APP-000101-NDM-000231'
  tag fix_id: 'F-22189r539177_fix'
  tag 'documentable'
  tag legacy: ['SV-110619', 'V-101515']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
