control 'SV-239707' do
  title 'vSphere UI must use a logging mechanism that is configured to allocate log record storage capacity large enough to accommodate the logging requirements of the web server.'
  desc 'To ensure that the logging mechanism used by the web server has sufficient storage capacity in which to write the logs, the logging mechanism needs to be able to allocate log record storage capacity. vSphere UI configures log sizes and rotation appropriately as part of its installation routine. Verifying that the logging configuration file (serviceability.xml) has not been modified is sufficient to determine if the logging configuration has been modified from the default.'
  desc 'check', 'At the command prompt, execute the following command:

# rpm -V vsphere-ui|grep serviceability.xml|grep "^..5......"

If the above command returns any output, this is a finding.'
  desc 'fix', 'Reinstall the VCSA or roll back to a snapshot. 

Modifying the vSphere UI installation files manually is not supported by VMware.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 UI Tomcat'
  tag check_id: 'C-42940r679225_chk'
  tag severity: 'medium'
  tag gid: 'V-239707'
  tag rid: 'SV-239707r879730_rule'
  tag stig_id: 'VCUI-67-000026'
  tag gtitle: 'SRG-APP-000357-WSR-000150'
  tag fix_id: 'F-42899r679226_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
