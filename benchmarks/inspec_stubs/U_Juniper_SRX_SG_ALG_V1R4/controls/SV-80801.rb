control 'SV-80801' do
  title 'The Juniper SRX Services Gateway Firewall must disable or remove unnecessary network services and functions that are not used as part of its role in the architecture.'
  desc 'Network devices are capable of providing a wide variety of functions (capabilities or processes) and services. Some of these functions and services are installed and enabled by default. The organization must determine which functions and services are required to perform the content filtering and other necessary core functionality for each component of the SRX. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Services that may be related security-related, but based on the role of the device in the architecture do not need to be installed. For example, the Juniper SRX can have an Antivirus, Web filter, IDS, or ALG license. However, if these functions are not part of the documented role of the SRX in the enterprise or branch architecture, then these the software and licenses should not be installed on the device. This mitigates the risk of exploitation of unconfigured services or services that are not kept updated with security fixes. If left unsecured, these services may provide a threat vector.

Only remove unauthorized services. This control is not intended to restrict the use of Juniper SRX devices with multiple authorized roles.'
  desc 'check', 'Review the documentation and architecture for the device.

<root> 
show system license

If unneeded services and functions are installed on the device, but are not part of the documented role of the device, this is a finding.'
  desc 'fix', 'Remove unnecessary services and functions. From operational mode, display the licenses available to be deleted; enter the following commands.

request system license delete license-identifier-list ?
request system license delete <license-identifier>

Note: Only remove unauthorized services. This control is not intended to restrict the use of Juniper SRX devices with multiple authorized roles.'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG ALG'
  tag check_id: 'C-66957r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66311'
  tag rid: 'SV-80801r1_rule'
  tag stig_id: 'JUSX-AG-000083'
  tag gtitle: 'SRG-NET-000131-ALG-000085'
  tag fix_id: 'F-72387r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
