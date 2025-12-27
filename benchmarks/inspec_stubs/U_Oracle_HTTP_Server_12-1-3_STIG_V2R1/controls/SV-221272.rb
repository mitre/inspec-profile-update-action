control 'SV-221272' do
  title 'OHS must have the mpm property set to use the worker Multi-Processing Module (MPM) as the preferred means to limit the number of allowed simultaneous requests.'
  desc 'Web server management includes the ability to control the number of users and user sessions that utilize a web server. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to several types of Denial of Service attacks. 

Although there is some latitude concerning the settings themselves, the settings should follow DoD-recommended values, but the settings should be configurable to allow for future DoD direction. While the DoD will specify recommended values, the values can be adjusted to accommodate the operational requirement of a given system.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ohs.plugins.nodemanager.properties file with an editor.

2. Search for the "mpm" property.

3. If the "mpm" property is omitted or commented out, this is a finding.

4. If the "mpm" property is not set to "worker", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ohs.plugins.nodemanager.properties with an editor.

2. Set the "mpm" property to a value of "worker", add the property if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-22987r414499_chk'
  tag severity: 'medium'
  tag gid: 'V-221272'
  tag rid: 'SV-221272r414501_rule'
  tag stig_id: 'OH12-1X-000001'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-22976r414500_fix'
  tag 'documentable'
  tag legacy: ['SV-77643', 'V-63153']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
