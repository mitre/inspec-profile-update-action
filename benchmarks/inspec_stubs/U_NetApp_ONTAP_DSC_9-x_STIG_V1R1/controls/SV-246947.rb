control 'SV-246947' do
  title 'ONTAP must be configured to authenticate each administrator prior to authorizing privileges based on assignment of group or role.'
  desc 'To assure individual accountability and prevent unauthorized access, administrators must be individually identified and authenticated.

Individual accountability mandates that each administrator is uniquely identified. A group authenticator is a shared account or some other form of authentication that allows multiple unique individuals to access the network device using a single account.

If a device allows or provides for group authenticators, it must first individually authenticate administrators prior to implementing group authenticator functionality.

Some devices may not have the need to provide a group authenticator; this is considered a matter of device design. In those instances where the device design includes the use of a group authenticator, this requirement will apply. This requirement applies to accounts created and managed on or by the network device.'
  desc 'check', 'Use "security login show -role admin -authentication-method domain" to see all configured admin users and groups that authenticate using active directory.

If ONTAP cannot be configured to authenticate each administrator prior to authorizing privileges based on assignment of group or role, this is a finding.'
  desc 'fix', 'Configure new administrator active directory users or groups with "security login create -user-or-group-name <user_name> -role admin -authentication-method domain".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50379r769171_chk'
  tag severity: 'medium'
  tag gid: 'V-246947'
  tag rid: 'SV-246947r769173_rule'
  tag stig_id: 'NAOT-IA-000001'
  tag gtitle: 'SRG-APP-000153-NDM-000249'
  tag fix_id: 'F-50333r769172_fix'
  tag 'documentable'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
