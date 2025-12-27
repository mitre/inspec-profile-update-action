control 'SV-254030' do
  title 'The Juniper router must not be configured to have any zero-touch deployment feature enabled when connected to an operational network.'
  desc 'Network devices configured via a zero-touch deployment or auto-loading feature can have their startup configuration or image pushed to the device for installation via TFTP or Remote Copy (rcp). Loading an image or configuration file from the network is taking a security risk because the file could be intercepted by an attacker who could corrupt the file, resulting in a denial of service.'
  desc 'check', 'Review the device configuration to determine if a configuration auto-loading or zero-touch deployment feature is enabled. Verify the Juniper router is not configured with the factory default configuration. The Zero Touch Provisioning (ZTP) feature requires the factory default configuration. Juniper ZTP leverages Dynamic Host Configuration Protocol (DHCP) options to provide not only the interface address, but also the location of the upgrade image and configuration file. Interfaces configured for DHCP will not attempt to establish a ZTP session simply because DHCP is enabled but, instead, also require a factory default configuration. Therefore, if DHCP is authorized, removing the following [edit system] options, setting a root password, and committing will prevent the device from attempting ZTP.

Verify the following are removed. 
[edit system]
:
:
auto-configuration; << Delete this command.
phone-home { << Delete this stanza.
    server <server URL>;
    rfc-compliant;
}

If a configuration auto-loading feature or zero-touch deployment feature is enabled, this is a finding.

Note: Auto-configuration or zero-touch deployment features can be enabled when the router is offline for the purpose of image loading or building out the configuration. In addition, this would not be applicable to the provisioning of virtual routers via a software-defined network (SDN) orchestration system.'
  desc 'fix', 'Disable all configuration auto-loading or zero-touch deployment features.

delete system auto-configuration
delete system phone-home
Note: The "phone-home" command is hidden and must be fully typed into the CLI (autocomplete will not work).

Configure the router with a nondefault configuration and commit.'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57482r844121_chk'
  tag severity: 'medium'
  tag gid: 'V-254030'
  tag rid: 'SV-254030r844123_rule'
  tag stig_id: 'JUEX-RT-000580'
  tag gtitle: 'SRG-NET-000362-RTR-000109'
  tag fix_id: 'F-57433r844122_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
