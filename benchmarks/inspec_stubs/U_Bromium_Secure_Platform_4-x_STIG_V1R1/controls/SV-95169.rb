control 'SV-95169' do
  title 'If the Host Based Security System (HBSS) is not installed to monitor the Bromium Enterprise Controller (BEC) application, processes, and registry settings, the Bromium Protection agent must be installed on the BEC server.'
  desc 'Installing the Bromium Protection agent on the BEC server will allow for monitoring and alerting on attempts to attack critical files, applications, processes, and registry settings on the BEC server, as well as attempts at executing unauthorized code in memory. All alerts will be sent to the BEC management server (along with any designated syslog destinations). Upon receipt of the alert, the system administrator must investigate and take appropriate action.

DoD requires the use of HBSS on all hosts, thus the Bromium Protection agent cannot be used to fulfill the requirement for HBSS. The Bromium Protection agent does not provide signature based antivirus or IDPS functions. However, it will monitor and notify the device memory as required by this CCI. The agent is compatible with HBSS and can be run at the same time. Installation of the agent is not mandatory unless there is a mission essential reason HBSS cannot be installed on the BEC host.'
  desc 'check', 'If HBSS is installed and configured to monitor the BEC application, processes, and registry settings, this is not a finding.

1. From the management console, select "Devices".
2. Click on "Add Filter" and select "Contains Text".
3. Click on the down arrow and enter the device name to search for the BEC server.
4. Once the desired BEC server is located, click on the device and inspect the "Monitoring Version" column to verify that the monitoring module is installed and enabled.

If the Bromium Protection agent is not installed and configured on the BEC server, this is a finding.'
  desc 'fix', 'If HBSS is not installed to monitor the BEC application, processes, and registry settings, install the Bromium Protection agent on the BEC server.

1. Install the Bromium agent on the BEC server (follow the on-screen instructions when deploying the ".msi" installation package).
2. Add the BEC server to a device group (this group may contain other/additional BEC servers).
3. Enable the monitoring policy for the BEC server.'
  impact 0.3
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80137r1_chk'
  tag severity: 'low'
  tag gid: 'V-80465'
  tag rid: 'SV-95169r1_rule'
  tag stig_id: 'BROM-00-001080'
  tag gtitle: 'SRG-APP-000450'
  tag fix_id: 'F-87271r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
