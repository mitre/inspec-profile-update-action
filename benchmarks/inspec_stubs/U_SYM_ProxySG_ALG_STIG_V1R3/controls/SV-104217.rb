control 'SV-104217' do
  title 'The reverse proxy Symantec ProxySG providing intermediary services for FTP must inspect inbound FTP communications traffic for protocol compliance and protocol anomalies.'
  desc 'Application protocol anomaly detection examines application layer protocols such as FTP to identify attacks based on observed deviations in the normal RFC behavior of a protocol or service. This type of monitoring allows for the detection of known and unknown exploits that exploit weaknesses of commonly used protocols.

Because protocol anomaly analysis examines the application payload for patterns or anomalies, an FTP proxy must be included in the ALG. This ALG will be configured to inspect inbound and outbound FTP communications traffic to detect protocol anomalies such as malformed message and command insertion attacks.'
  desc 'check', 'Verify that FTP reverse proxy intermediary services are configured.

1. Verify with the ProxySG administrator that FTP reverse proxy services are configured. 
2. Log on to the Web Management Console. 
3. Click Configuration >> Services >> Proxy Services. 
4. For each FTP reverse proxy service identified by the administrator, verify that the Action is set to "intercept".
5. Browse to Configuration >> Forwarding Hosts. Verify that the back-end FTP server is specified in the list.
6. Browse to Policy >> Visual Policy Manager" and click "Launch".
7. Verify that a Forwarding Layer exists that references the Forwarding Host configured in step 5.

If the reverse proxy Symantec ProxySG providing intermediary services for FTP does not inspect inbound FTP communications traffic for protocol compliance and protocol anomalies, this is a finding.'
  desc 'fix', 'Configure FTP reverse proxy intermediary services.

See the ProxySG Reverse Proxy WebGuide for details.

1. Log on to the Web Management Console. 
2. Click Configuration >> Services >> Proxy Services. 
3. Click "New Service" and create new FTP proxy services with the Action set to "intercept".
4. Browse to Configuration >> Forwarding Hosts. Click "New" and create an entry for the desired back-end FTP server. Click "Apply".
5. Browse to Policy >> Visual Policy Manager and click "Launch".
6. Click Policy >> Add Forwarding Layer. In the default rule, set the Action to be the Forwarding Host configured in step 4.
7. Click File >> Install Policy on SG Appliance.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93449r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94263'
  tag rid: 'SV-104217r1_rule'
  tag stig_id: 'SYMP-AG-000240'
  tag gtitle: 'SRG-NET-000512-ALG-000065'
  tag fix_id: 'F-100379r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001125']
  tag nist: ['CM-6 b', 'SC-7 (17)']
end
