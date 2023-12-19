control 'SRG-NET-000042-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must retain the Standard Mandatory DOD Notice and Consent Banner on the screen for management sessions until admins acknowledge the usage conditions and take explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the user prior to allowing the user access to the network. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DOD will not be in compliance with system use notifications required by law. 

To establish acceptance of the application usage policy, a click-through banner at application logon is required. The network element must prevent further activity until the user executes a positive action to manifest agreement by clicking on a box indicating "OK". 

This requirement applies to network elements that have the concept of a user account and have the logon function residing on the network element.'
  desc 'check', 'Verify the Unified Communications Session Manager retains the Standard Mandatory DOD Notice and Consent Banner for management sessions until the admins acknowledge the conditions.

If the Unified Communications Session Manager does not retain the Standard Mandatory DOD Notice and Consent Banner until the admins acknowledge the conditions, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to retain the Standard Mandatory DOD Notice and Consent Banner for management sessions until the admins acknowledge the conditions.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000042-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000042-VVSM-00101'
  tag rid: 'SRG-NET-000042-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000042-VVSM-00101'
  tag gtitle: 'SRG-NET-000042-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000042-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
