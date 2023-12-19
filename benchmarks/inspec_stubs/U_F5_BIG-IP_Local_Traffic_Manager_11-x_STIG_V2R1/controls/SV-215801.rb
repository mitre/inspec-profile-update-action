control 'SV-215801' do
  title 'The BIG-IP Core implementation must be configured to inspect for protocol compliance and protocol anomalies in inbound SMTP and Extended SMTP communications traffic to virtual servers.'
  desc 'Application protocol anomaly detection examines application layer protocols such as SMTP to identify attacks based on observed deviations in the normal RFC behavior of a protocol or service. This type of monitoring allows for the detection of known and unknown exploits that exploit weaknesses of commonly used protocols.

Since protocol anomaly analysis examines the application payload for patterns or anomalies, an SMTP proxy must be included in the ALG. This ALG will be configured to inspect inbound SMTP and Extended SMTP communications traffic to detect protocol anomalies such as malformed message and command insertion attacks.'
  desc 'check', 'If the BIG-IP Core does not provide intermediary/proxy services for SMTP communications traffic for virtual servers, this is not applicable.

When intermediary/proxy services for SMTP communication traffic are provided, verify the BIG-IP Core is configured as follows:

Verify the BIG-IP LTM module is configured to inspect for protocol compliance and protocol anomalies in inbound SMTP and Extended SMTP communications traffic.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select a Virtual Server that has been configured as an SMTP proxy.

Verify that "SMTP Profile" under the "Configuration" section is set to a locally configured SMTP profile.

Verify the configuration of the selected SMTP profile:

Navigate to the BIG-IP System manager >> Local Traffic >> Profiles >> Services >> SMTP.

Select the SMTP profile that was to configure the Virtual Server.

Verify that "Protocol Security" is Enabled under the "Settings" section.

If the BIG-IP Core does not inspect inbound SMTP and Extended SMTP communications traffic for protocol compliance and protocol anomalies, this is a finding.'
  desc 'fix', 'If the BIG-IP Core provides intermediary/proxy services for SMTP communications traffic, configure the BIG-IP Core as follows:

Configure the BIG-IP LTM module to inspect for protocol compliance and protocol anomalies in inbound SMTP and Extended SMTP communications traffic.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16993r291216_chk'
  tag severity: 'medium'
  tag gid: 'V-215801'
  tag rid: 'SV-215801r557356_rule'
  tag stig_id: 'F5BI-LT-000303'
  tag gtitle: 'SRG-NET-000512-ALG-000064'
  tag fix_id: 'F-16991r291217_fix'
  tag 'documentable'
  tag legacy: ['V-60383', 'SV-74813']
  tag cci: ['CCI-001125', 'CCI-000366']
  tag nist: ['SC-7 (17)', 'CM-6 b']
end
