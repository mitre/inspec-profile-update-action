control 'SV-230959' do
  title 'Forescout must be configured to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

Forescout is capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

Wireless is an example only of a service that is frequently unnecessary in many Forescout implementations. Reword more generically and be sure to look for module that are not part of the UC ACL default and may have been installed by the site and therefore are not authorized for use in DoD.'
  desc 'check', 'Navigate to the plugin tool and remove all unneeded or unsecure services.

1. Connect to the Forescout Console and select Tools >> Options >> Plugins.
2. Review the list of plugins. If an unnecessary or nonsecure service is "Enabled", select the plugin and then select "Configure".

If no configuration is present, this is a finding.

If any unnecessary or nonsecure functions are enabled, this is a finding.'
  desc 'fix', 'Configure the network device to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services. The following is an example of disabling the wireless plugin if no wireless devices are directly managed by Forescout.

Example ONLY:

1. Connect to the Forescout Console and select Tools >> Options >> Modules >> Network.
2. Determine if the wireless plugin is running. If it is running, click the option and click "Stop". If the user is logged in to the enterprise manager, this will stop it on all the appliances in the enterprise.

This process can be used to disable or remove plugins not being used.'
  impact 0.7
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33889r603716_chk'
  tag severity: 'high'
  tag gid: 'V-230959'
  tag rid: 'SV-230959r615886_rule'
  tag stig_id: 'FORE-NM-000330'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-33862r603717_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
