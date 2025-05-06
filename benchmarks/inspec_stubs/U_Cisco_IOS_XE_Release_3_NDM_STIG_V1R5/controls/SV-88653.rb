control 'SV-88653' do
  title 'The Cisco IOS XE router must protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.'
  desc 'This requirement supports non-repudiation of actions taken by an administrator and is required in order to maintain the integrity of the configuration management process. All configuration changes to the network device are logged, and administrators authenticate with two-factor authentication before gaining administrative access. Together, these processes will ensure the administrators can be held accountable for the configuration changes they implement.

To meet this requirement, the network device must log administrator access and activity.'
  desc 'check', 'Review the Cisco IOS XE router configuration to determine if logging is enabled to prevent repudiation.

The configuration should look similar to the example below:

logging userinfo
archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys

If logging is not enabled, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router to enable logging.

The configuration should like similar to the example below:

logging userinfo
archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74061r3_chk'
  tag severity: 'low'
  tag gid: 'V-73979'
  tag rid: 'SV-88653r2_rule'
  tag stig_id: 'CISR-ND-000021'
  tag gtitle: 'SRG-APP-000080-NDM-000220'
  tag fix_id: 'F-80519r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
