control 'SV-104295' do
  title 'Reverse proxy Symantec ProxySG providing content filtering must continuously monitor inbound communications traffic crossing internal security boundaries for unusual or unauthorized activities or conditions.'
  desc 'If inbound communications traffic is not continuously monitored, hostile activity may not be detected and prevented. Output from application and traffic monitoring serves as input to continuous monitoring and incident response programs.

Internal monitoring includes the observation of events occurring on the network as they cross internal boundaries at managed interfaces such as web content filters. Depending on the type of ALG, organizations can monitor information systems by monitoring audit activities, application access patterns, characteristics of access, content filtering, or unauthorized exporting of information across boundaries. Unusual/unauthorized activities or conditions may include large file transfers, long-time persistent connections, unusual protocols and ports in use, and attempted communications with suspected malicious external addresses.'
  desc 'check', 'Verify that the ProxySG is configured to monitor inbound communication traffic for unusual or unauthorized activities or conditions.

1. Log on to the Web Management Console.
2. Browse to "Configuration" and click "Access Logging". Verify that "Enable Access Logging" is checked.
3. Click Policy >> Visual Policy Manager >> Launch.
4. For each Web Access Layer, verify that each rule has a value other than "none" in the "Track" column.

If reverse proxy Symantec ProxySG providing content filtering does not continuously monitor inbound communications traffic crossing internal security boundaries for unusual or unauthorized activities or conditions, this is a finding.'
  desc 'fix', 'Configure the ProxySG to monitor inbound communication traffic for unusual or unauthorized activities or conditions.

1. Log on to the Web Management Console.
2. Browse to "Configuration" and click "Access Logging". Check the "Enable Access Logging" option and click "Apply".
3. Click Policy >> Visual Policy Manager >> Launch.
4. For each Web Access Layer, right-click the "Track" column for each rule and select "Set".
5. Click "New" and select "Event Log".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93527r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94341'
  tag rid: 'SV-104295r1_rule'
  tag stig_id: 'SYMP-AG-000640'
  tag gtitle: 'SRG-NET-000390-ALG-000139'
  tag fix_id: 'F-100457r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002661']
  tag nist: ['SI-4 (4) (b)']
end
