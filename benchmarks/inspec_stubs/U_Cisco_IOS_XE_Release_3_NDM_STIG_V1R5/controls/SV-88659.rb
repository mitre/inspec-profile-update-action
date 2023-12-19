control 'SV-88659' do
  title 'The Cisco IOS XE router must generate audit records when successful/unsuccessful attempts to access privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify that the Cisco IOS XE router is configured to generate audit records when successful/unsuccessful attempts to access privileges.

The configuration should look similar to the example below:

logging userinfo

login on-failure log
login on-success log

archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys

If audit records are not being generated, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router to enable auditing.

The configuration should look similar to the example below:

logging userinfo

login on-failure log
login on-success log

archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74067r3_chk'
  tag severity: 'medium'
  tag gid: 'V-73985'
  tag rid: 'SV-88659r2_rule'
  tag stig_id: 'CISR-ND-000025'
  tag gtitle: 'SRG-APP-000091-NDM-000223'
  tag fix_id: 'F-80525r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
