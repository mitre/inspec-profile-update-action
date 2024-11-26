control 'SV-90911' do
  title 'CounterACT must disable all unnecessary and/or nonsecure plugins.'
  desc 'CounterACT is capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component.

If the 802.1x plugin is installed and there are no wireless APs or controllers directly managed by CounterACT, the wireless plugin should be disabled. The wireless plugin enabled with no configuration will also produce a finding.'
  desc 'check', 'Navigate to the plugin tool and remove all unneeded or unsecure services.

1. Connect to the CounterACT Console and select Tools >> Options >> Plugins.
2. Review the list of plugins. If an unnecessary or nonsecure service is "Enabled", select the plugin and then select "Configure".

If no configuration is present, this is a finding.

If any unnecessary or nonsecure functions are enabled, this is a finding.'
  desc 'fix', 'Configure the network device to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services. The following is an example of disabling the wireless plugin if no wireless devices are directly managed by CounterACT.

Example:
1. Connect to the CounterACT Console and select Tools >> Options >> Plugins.
2. Determine if the wireless plugin status is "Enabled", select the plugin, and select "Stop" (for all appliances).

This process can be used to disable or remove plugins not being used.'
  impact 0.7
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75909r1_chk'
  tag severity: 'high'
  tag gid: 'V-76223'
  tag rid: 'SV-90911r1_rule'
  tag stig_id: 'CACT-NM-000025'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-82859r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
