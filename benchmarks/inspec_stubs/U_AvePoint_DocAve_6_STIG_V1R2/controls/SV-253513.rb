control 'SV-253513' do
  title 'DocAve must provide automated mechanisms for supporting account management functions.'
  desc 'Remote access (e.g., Remote Desktop Protocol [RDP]) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.'
  desc 'check', 'DocAve supports integration with Active Directory (AD) for automated account management.

Check the DocAve configuration to ensure AD Integration is enabled.
- Log on to DocAve with admin account.
- On the Control Panel page, in the Authentication Manager section, click "Authentication Manager".
- Navigate to AD Integration.
- Verify that the AD Integration option is enabled.

If the AD Integration option is not enabled, this is a finding.'
  desc 'fix', 'Configure the DocAve configuration to ensure AD Integration is enabled.
- Log on to DocAve with admin account.
- On the Control Panel page, in the Authentication Manager section, click "Authentication Manager".
- Navigate to AD Integration.
- Set the Action of AD Integration to Enable.
- Save settings.

Add AD user or group to DocAve by Account Manager, realize automated mechanisms through AD account management functions.'
  impact 0.5
  ref 'DPMS Target AvePoint DocAve 6'
  tag check_id: 'C-56965r836512_chk'
  tag severity: 'medium'
  tag gid: 'V-253513'
  tag rid: 'SV-253513r836514_rule'
  tag stig_id: 'DCAV-00-000009'
  tag gtitle: 'SRG-APP-000023'
  tag fix_id: 'F-56916r836513_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
