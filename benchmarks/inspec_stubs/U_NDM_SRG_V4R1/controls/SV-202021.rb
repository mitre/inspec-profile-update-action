control 'SV-202021' do
  title 'The network device must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until the administrator acknowledges the usage conditions and takes explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the administrator prior to the device allowing the administrator access to the network device. This provides assurance that the administrator has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the administrator, DoD will not be in compliance with system use notifications required by law. 

To establish acceptance of the network administration policy, a click-through banner at management session logon is required. The device must prevent further activity until the administrator executes a positive action to manifest agreement.

In the case of CLI access using a terminal client, entering the username and password when the banner is presented is considered an explicit action of acknowledgement. Entering the username, viewing the banner, then entering the password is also acceptable.'
  desc 'check', 'Determine if the network device is configured to retain the Standard Mandatory DoD Notice and Consent Banner on the screen until the administrator acknowledges the usage conditions and takes explicit actions to log on for further access. If the network device does not retain the banner on the screen until the administrator acknowledges the usage conditions and takes explicit actions to log on for further access, this is a finding.'
  desc 'fix', 'Configure the network device to retain the Standard Mandatory DoD Notice and Consent Banner on the screen until the administrator acknowledges the usage conditions and takes explicit actions to log on for further access.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2147r381593_chk'
  tag severity: 'medium'
  tag gid: 'V-202021'
  tag rid: 'SV-202021r395613_rule'
  tag stig_id: 'SRG-APP-000069-NDM-000216'
  tag gtitle: 'SRG-APP-000069'
  tag fix_id: 'F-2148r381594_fix'
  tag 'documentable'
  tag legacy: ['SV-69305', 'V-55059']
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
