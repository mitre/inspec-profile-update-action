control 'SV-214177' do
  title 'In the event of a system failure, The Infoblox system must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving application state information helps to facilitate application restart and return to the operational mode of the organization with less disruption to mission-essential processes.'
  desc 'check', 'By default all system events are logged to the local SYSLOG. To ensure logging of data in the event of system failure, an external log server must be configured.

Navigate to Grid >> Grid Manager >> Grid Properties >> Monitoring tab.

When complete, click "Cancel" to exit the "Properties" screen.

If "Log to External Syslog Servers" is enabled, an External Syslog Server must be configured and "Copy Audit Log Message to Syslog" must be configured otherwise, this is a finding.'
  desc 'fix', 'Navigate to Grid >> Grid Manager >> Grid Properties >> Monitoring tab.

Enable "Log to External Syslog Server", Configure at least one "External Syslog Servers".
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15392r295794_chk'
  tag severity: 'medium'
  tag gid: 'V-214177'
  tag rid: 'SV-214177r612370_rule'
  tag stig_id: 'IDNS-7X-000310'
  tag gtitle: 'SRG-APP-000226-DNS-000032'
  tag fix_id: 'F-15390r295795_fix'
  tag 'documentable'
  tag legacy: ['V-68549', 'SV-83039']
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
