control 'SV-220994' do
  title 'The Cisco switch must not be configured to have any zero-touch deployment feature enabled when connected to an operational network.'
  desc 'Network devices that are configured via a zero-touch deployment or auto-loading feature can have their startup configuration or image pushed to the device for installation via TFTP or Remote Copy (rcp). Loading an image or configuration file from the network is taking a security risk because the file could be intercepted by an attacker who could corrupt the file, resulting in a denial of service.'
  desc 'check', 'Review the device configuration to determine if auto-configuration or zero-touch deployment via Cisco Networking Services (CNS) is enabled. 

Auto-Configuration Example:

version 15.0
service config
…
…
…
boot-start-marker
boot network tftp://x.x.x.x/R5-config
boot-end-marker

CNS Zero-Touch Example:

cns trusted-server config x.x.x.x
cns trusted-server image x.x.x.x
cns config initial x.x.x.x 80
cns exec 80
cns image

If a configuration auto-loading feature or zero-touch deployment feature is enabled, this is a finding. 

Note: Auto-configuration or zero-touch deployment features can be enabled when the switch is offline for the purpose of image loading or building out the configuration. In addition, this would not be applicable to the provisioning of virtual switches via a software-defined network (SDN) orchestration system.'
  desc 'fix', 'Disable configuration auto-loading if enabled using the following commands:

SW1(config)#no boot network
SW1(config)#no service config

Disable CNS zero-touch deployment if enabled as shown in the example below:

SW2(config)#no cns config initial
SW2(config)#no cns exec
SW2(config)#no cns image
SW2(config)#no cns trusted-server config x.x.x.x
SW2(config)#no cns trusted-server image x.x.x.x'
  impact 0.5
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22709r408776_chk'
  tag severity: 'medium'
  tag gid: 'V-220994'
  tag rid: 'SV-220994r856401_rule'
  tag stig_id: 'CISC-RT-000090'
  tag gtitle: 'SRG-NET-000362-RTR-000109'
  tag fix_id: 'F-22698r408777_fix'
  tag 'documentable'
  tag legacy: ['SV-110809', 'V-101705']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
