control 'SV-207149' do
  title 'The router must not be configured to have any zero-touch deployment feature enabled when connected to an operational network.'
  desc 'Network devices that are configured via a zero-touch deployment or auto-loading feature can have their startup configuration or image pushed to the device for installation via TFTP or Remote Copy (rcp). Loading an image or configuration file from the network is taking a security risk because the file could be intercepted by an attacker who could corrupt the file, resulting in a denial of service.'
  desc 'check', 'Review the device configuration to determine if a configuration auto-loading or zero-touch deployment feature is enabled.

If a configuration auto-loading feature or zero-touch deployment feature is enabled, this is a finding.

Note: Auto-configuration or zero-touch deployment features can be enabled when the router is offline for the purpose of image loading or building out the configuration. In addition, this would not be applicable to the provisioning of virtual routers via a software-defined network (SDN) orchestration system.'
  desc 'fix', 'Disable all configuration auto-loading or zero-touch deployment features.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7410r382430_chk'
  tag severity: 'medium'
  tag gid: 'V-207149'
  tag rid: 'SV-207149r604135_rule'
  tag stig_id: 'SRG-NET-000362-RTR-000109'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-7410r382431_fix'
  tag 'documentable'
  tag legacy: ['SV-92919', 'V-78213']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
