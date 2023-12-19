control 'SV-222586' do
  title 'In the event of a system failure, applications must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving application state information helps to facilitate application restart and return to the operational mode of the organization with less disruption to mission-essential processes.'
  desc 'check', 'Review application documentation, interview application administrator to identify how the application logs error events.

The application operational requirements documentation should provide the specific information that must be preserved in order to return the application back into operation as quickly and efficiently as possible. The application administrator will need to identify and provide the information based upon operational requirements documents.

Application diagnostic information should be kept in logs for evaluation and investigation into root cause.

If documentation is provided stating that no particular information needs to be retained in order to expediently bring the application back online, this is not a finding.

If the application does not log the data required to determine root cause of application failure, or if information specified as required in order to expediently bring the application back online is not retained, this is a finding.'
  desc 'fix', 'Create operational configuration documentation that identifies information needed for the application to return back into service or specify no such data is required, and retain data required to determine root cause of application failures.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24256r493666_chk'
  tag severity: 'medium'
  tag gid: 'V-222586'
  tag rid: 'SV-222586r508029_rule'
  tag stig_id: 'APSC-DV-002320'
  tag gtitle: 'SRG-APP-000226'
  tag fix_id: 'F-24245r493667_fix'
  tag 'documentable'
  tag legacy: ['SV-84845', 'V-70223']
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
