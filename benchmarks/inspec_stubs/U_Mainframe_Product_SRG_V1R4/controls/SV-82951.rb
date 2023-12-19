control 'SV-82951' do
  title 'In the event of application failure, Mainframe Products must preserve any information necessary to determine the cause of failure and any information necessary to return to operations with the least disruption to mission processes.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving application state information helps to facilitate application restart and return to the operational mode of the organization with less disruption to mission-essential processes.'
  desc 'check', 'Examine installation and configuration settings.

If the Mainframe Product is not configured to preserve information necessary to determine cause of failure and to assist in the return to normal operation, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to preserve information necessary to determine cause of failure and to assist in the return to normal operation.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68993r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68461'
  tag rid: 'SV-82951r1_rule'
  tag stig_id: 'SRG-APP-000226-MFP-000301'
  tag gtitle: 'SRG-APP-000226-MFP-000301'
  tag fix_id: 'F-74577r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
