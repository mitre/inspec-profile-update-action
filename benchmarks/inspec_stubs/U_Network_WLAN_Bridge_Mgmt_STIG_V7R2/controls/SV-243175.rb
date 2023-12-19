control 'SV-243175' do
  title 'The network device must be configured to authenticate each administrator prior to authorizing privileges based on assignment of group or role.'
  desc 'To ensure individual accountability and prevent unauthorized access, administrators must be individually identified and authenticated.

Individual accountability mandates that each administrator is uniquely identified. A group authenticator is a shared account or some other form of authentication that allows multiple unique individuals to access the network device using a single account. 

If a device allows or provides for group authenticators, it must individually authenticate administrators prior to implementing group authenticator functionality. 

Some devices may not have the need to provide a group authenticator; this is considered a matter of device design. Where the device design includes the use of a group authenticator, this requirement will apply. This requirement applies to accounts created and managed on or by the network device.'
  desc 'check', 'Review the network device configuration and validate that users are authenticated before they are assigned privileges based on the role or group the account is assigned to.

If a user can gain access to network device privileges before they are authenticated, this is a finding.'
  desc 'fix', 'Configure the network device to authenticate users before assigning privileges to each individual user account based on the role or group the account is assigned to.'
  impact 0.5
  ref 'DPMS Target Network WLAN Bridge Mgmt'
  tag check_id: 'C-46450r719978_chk'
  tag severity: 'medium'
  tag gid: 'V-243175'
  tag rid: 'SV-243175r879594_rule'
  tag stig_id: 'WLAN-ND-000600'
  tag gtitle: 'SRG-APP-000153-NDM-000249'
  tag fix_id: 'F-46407r719979_fix'
  tag 'documentable'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
