control 'SV-88735' do
  title 'The Cisco IOS XE router must generate audit records when successful/unsuccessful attempts to modify administrator privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Review the Cisco IOS XE router configuration to determine if it automatically audits account modification.

The configuration should look similar to the example below:

logging userinfo

archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys

If account modification is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router for auditing.

The configuration should look similar to the example below:

logging userinfo

archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74151r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74061'
  tag rid: 'SV-88735r2_rule'
  tag stig_id: 'CISR-ND-000121'
  tag gtitle: 'SRG-APP-000495-NDM-000318'
  tag fix_id: 'F-80629r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
