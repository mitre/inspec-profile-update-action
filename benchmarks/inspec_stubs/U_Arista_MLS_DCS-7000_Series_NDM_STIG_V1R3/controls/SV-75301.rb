control 'SV-75301' do
  title 'The Arista Multilayer Switch must protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.'
  desc 'This requirement supports non-repudiation of actions taken by an administrator and is required in order to maintain the integrity of the configuration management process. All configuration changes to the network device are logged, and administrators authenticate with two-factor authentication before gaining administrative access. Together, these processes will ensure the administrators can be held accountable for the configuration changes they implement.

To meet this requirement, the network device must log administrator access and activity.'
  desc 'check', 'Review the switch configuration and verify that logging is enabled.

If logging is not enabled or is not enabled with sufficient detail to fulfill the specifications set forth in the VulDiscussion, this is a finding.

To determine if logging is enabled, enter: 

switch#show logging

The output must show logging as enabled, with a logging level of informational or debugging.

In order to ensure all user commands are captured, the following statement must be in the running config:

aaa accounting commands all default start-stop logging [group radius]'
  desc 'fix', 'Enable logging on the switch with sufficient detail to fulfill the specifications set forth in the VulDiscussion.

To configure logging to a remote syslog server at the informational level, enter:

switch#config
switch(config)#logging host [ip address]
switch(config)#logging trap informational

Then configure the following AAA

aaa accounting commands all default start-stop logging [group radius]'
  impact 0.3
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61791r1_chk'
  tag severity: 'low'
  tag gid: 'V-60845'
  tag rid: 'SV-75301r1_rule'
  tag stig_id: 'AMLS-NM-000170'
  tag gtitle: 'SRG-APP-000080-NDM-000220'
  tag fix_id: 'F-66555r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
