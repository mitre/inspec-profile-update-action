control 'SV-255951' do
  title 'The Arista network device must be configured to audit all administrator activity.'
  desc 'This requirement supports non-repudiation of actions taken by an administrator and is required in order to maintain the integrity of the configuration management process. All configuration changes to the network device are logged, and administrators authenticate with two-factor authentication before gaining administrative access. Together, these processes will ensure the administrators can be held accountable for the configuration changes they implement.

'
  desc 'check', 'Verify the Arista network device is configured to audit all administrator activity.

Verify the AAA logging settings in the configuration file with the following example:

switch#show running-config | section aaa

aaa authentication policy on-success log
aaa authentication policy on-failure log
aaa accounting exec default start-stop group radius logging
aaa accounting system default start-stop group radius logging
aaa accounting commands all default start-stop logging group radius

If the Arista network device is not configured to audit all administrator activity, this is a finding.'
  desc 'fix', 'Configure the Arista network device to audit all administrator activity.

Configure the AAA settings to capture administrator activity events.

switch(config)#aaa authentication policy on-success log
switch(config)#aaa authentication policy on-failure log
switch(config)#aaa accounting exec default start-stop group radius logging
switch(config)#aaa accounting system default start-stop group radius logging
switch(config)#aaa accounting commands all default start-stop logging group radius'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59627r882193_chk'
  tag severity: 'medium'
  tag gid: 'V-255951'
  tag rid: 'SV-255951r882195_rule'
  tag stig_id: 'ARST-ND-000150'
  tag gtitle: 'SRG-APP-000026-NDM-000208'
  tag fix_id: 'F-59570r882194_fix'
  tag satisfies: ['SRG-APP-000026-NDM-000208', 'SRG-APP-000027-NDM-000209', 'SRG-APP-000028-NDM-000210', 'SRG-APP-000029-NDM-000211', 'SRG-APP-000080-NDM-000220', 'SRG-APP-000091-NDM-000223', 'SRG-APP-000101-NDM-000231', 'SRG-APP-000319-NDM-000283', 'SRG-APP-000343-NDM-000289', 'SRG-APP-000495-NDM-000318', 'SRG-APP-000499-NDM-000319', 'SRG-APP-000503-NDM-000320', 'SRG-APP-000504-NDM-000321', 'SRG-APP-000506-NDM-000323']
  tag 'documentable'
  tag cci: ['CCI-000018', 'CCI-000135', 'CCI-000166', 'CCI-000172', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-002130', 'CCI-002234']
  tag nist: ['AC-2 (4)', 'AU-3 (1)', 'AU-10', 'AU-12 c', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-6 (9)']
end
