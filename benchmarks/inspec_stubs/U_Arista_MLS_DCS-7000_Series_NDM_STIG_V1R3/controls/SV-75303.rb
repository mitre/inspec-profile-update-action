control 'SV-75303' do
  title 'The Arista Multilayer Switch must generate audit records when successful/unsuccessful attempts to access privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
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

Then configure the following AAA:

aaa accounting commands all default start-stop logging [group radius]'
  impact 0.3
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61793r1_chk'
  tag severity: 'low'
  tag gid: 'V-60847'
  tag rid: 'SV-75303r1_rule'
  tag stig_id: 'AMLS-NM-000180'
  tag gtitle: 'SRG-APP-000091-NDM-000223'
  tag fix_id: 'F-66557r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
