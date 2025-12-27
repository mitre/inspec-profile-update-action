control 'SV-215802' do
  title 'The BIG-IP Core implementation must be configured to inspect for protocol compliance and protocol anomalies in inbound FTP and FTPS communications traffic to virtual servers.'
  desc 'Application protocol anomaly detection examines application layer protocols such as FTP to identify attacks based on observed deviations in the normal RFC behavior of a protocol or service. This type of monitoring allows for the detection of known and unknown exploits that exploit weaknesses of commonly used protocols.

Since protocol anomaly analysis examines the application payload for patterns or anomalies, an FTP proxy must be included in the ALG. This ALG will be configured to inspect inbound FTP and FTPS communications traffic to detect protocol anomalies such as malformed message and command insertion attacks.'
  desc 'check', 'If the BIG-IP Core does not provide intermediary/proxy services for FTP and FTPS communications traffic for virtual servers, this is not applicable.

When intermediary/proxy services for FTP and FTPS communications traffic are provided, verify the BIG-IP Core is configured as follows:

Verify the BIG-IP LTM module is configured to inspect for protocol compliance and protocol anomalies in inbound FTP and FTPS communications traffic.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select a Virtual Server that has been configured as an FTP proxy.

Verify that "FTP Profile" under the "Configuration" section is set to a locally configured FTP profile.

Verify the configuration of the selected FTP profile:

Navigate to the BIG-IP System manager >> Local Traffic >> Profiles >> Services >> FTP.

Select the FTP profile that was to configure the Virtual Server.

Verify that "Protocol Security" is Enabled under the "Settings" section.

If the BIG-IP Core does not inspect inbound FTP and FTPS communications traffic for protocol compliance and protocol anomalies, this is a finding.'
  desc 'fix', 'If the BIG-IP Core provides intermediary/proxy services for FTP and FTPS communications traffic, configure the BIG-IP Core as follows:

Configure the BIG-IP LTM module to inspect for protocol compliance and protocol anomalies in inbound FTP and FTPS communications traffic.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16994r291219_chk'
  tag severity: 'medium'
  tag gid: 'V-215802'
  tag rid: 'SV-215802r557356_rule'
  tag stig_id: 'F5BI-LT-000305'
  tag gtitle: 'SRG-NET-000512-ALG-000065'
  tag fix_id: 'F-16992r291220_fix'
  tag 'documentable'
  tag legacy: ['SV-74815', 'V-60385']
  tag cci: ['CCI-000366', 'CCI-001125']
  tag nist: ['CM-6 b', 'SC-7 (17)']
end
