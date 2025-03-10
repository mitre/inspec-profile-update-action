control 'SV-256029' do
  title 'The Arista router must not be configured to have any zero-touch deployment feature enabled when connected to an operational network.'
  desc 'Network devices that are configured via a zero-touch deployment or auto-loading feature can have their startup configuration or image pushed to the device for installation via TFTP or Remote Copy (rcp). Loading an image or configuration file from the network is taking a security risk because the file could be intercepted by an attacker who could corrupt the file, resulting in a denial of service.'
  desc 'check', 'Review the Arista MLS device configuration to determine if a configuration auto-loading or zero-touch deployment feature is enabled.

Execute the command "sh zerotouch".

Zerotouch Mode: Disabled

If a configuration auto-loading feature or zero-touch deployment feature is enabled, this is a finding.'
  desc 'fix', 'Disable all configuration auto-loading or zero-touch deployment features.

LEAF-1A(config)#zerotouch disable'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59705r882427_chk'
  tag severity: 'medium'
  tag gid: 'V-256029'
  tag rid: 'SV-256029r882429_rule'
  tag stig_id: 'ARST-RT-000490'
  tag gtitle: 'SRG-NET-000362-RTR-000109'
  tag fix_id: 'F-59648r882428_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
