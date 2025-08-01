control 'SV-242641' do
  title 'The Cisco ISE must be configured to disable Wireless Setup for production systems.'
  desc 'ISE Wireless Setup is beta software so is not authorized for use in DoD.

Wireless Setup is disabled by default after fresh installation of Cisco ISE. If you upgrade ISE from a previous version, the Wireless Setup menu does not appear. Wireless Setup requires ports 9103 and 9104 to be open. To close those ports, use the CLI to disable Wireless Setup.

You can enable Wireless Setup in the ISE CLI with the command application configure ise, picking the option to enable Wireless Setup.'
  desc 'check', 'If wireless setup is not availabe in this version of the product, this is not applicable.

Verify Wi-Fi setup has been disabled on a device after initial setup and the device has been placed on the production network.

Show application status Wi-Fi setup.

If wireless setup is not disabled, this is a finding.'
  desc 'fix', 'Use the application configure command in EXEC mode to disable wireless setup.

application configure disable Wi-Fi setup'
  impact 0.7
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45916r822758_chk'
  tag severity: 'high'
  tag gid: 'V-242641'
  tag rid: 'SV-242641r879588_rule'
  tag stig_id: 'CSCO-NM-000360'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-45873r714232_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
