control 'SV-104219' do
  title 'Symantec ProxySG providing intermediary services for FTP must inspect outbound FTP communications traffic for protocol compliance and protocol anomalies.'
  desc 'Application protocol anomaly detection examines application layer protocols such as FTP to identify attacks based on observed deviations in the normal RFC behavior of a protocol or service. This type of monitoring allows for the detection of known and unknown exploits that exploit weaknesses of commonly used protocols.

Since protocol anomaly analysis examines the application payload for patterns or anomalies, an FTP proxy must be included in the ALG. This ALG will be configured to inspect inbound and outbound FTP communications traffic to detect protocol anomalies such as malformed message and command insertion attacks.'
  desc 'check', 'Determine whether FTP proxying is enabled to provide inspection.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Services >> Proxy Services.
3. Click the "Standard", "Predefined Service Group" and verify that the FTP service is set to "Intercept".

If Symantec ProxySG providing intermediary services for FTP does not inspect outbound FTP communications traffic for protocol compliance and protocol anomalies, this is a finding.'
  desc 'fix', 'Enable outbound FTP proxying to inspect this traffic for compliance and anomalies.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Services >> Proxy Services.
3. Click the "Standard", "Predefined Service Group" and set FTP service to "Intercept". 
4. Click "Apply".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93451r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94265'
  tag rid: 'SV-104219r1_rule'
  tag stig_id: 'SYMP-AG-000250'
  tag gtitle: 'SRG-NET-000512-ALG-000065'
  tag fix_id: 'F-100381r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001125']
  tag nist: ['CM-6 b', 'SC-7 (17)']
end
