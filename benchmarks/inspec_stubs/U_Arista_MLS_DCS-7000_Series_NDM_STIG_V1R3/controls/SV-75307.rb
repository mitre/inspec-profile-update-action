control 'SV-75307' do
  title 'The Arista Multilayer Switch must generate audit records containing the full-text recording of privileged commands.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. 

Organizations consider limiting the additional audit information to only that information explicitly needed for specific audit requirements. The additional information required is dependent on the type of information (i.e., sensitivity of the data and the environment within which it resides). At a minimum, the organization must audit full-text recordings of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.'
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
  tag check_id: 'C-61797r1_chk'
  tag severity: 'low'
  tag gid: 'V-60851'
  tag rid: 'SV-75307r1_rule'
  tag stig_id: 'AMLS-NM-000200'
  tag gtitle: 'SRG-APP-000101-NDM-000231'
  tag fix_id: 'F-66561r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
