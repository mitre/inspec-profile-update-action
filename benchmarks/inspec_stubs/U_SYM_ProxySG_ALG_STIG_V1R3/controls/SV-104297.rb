control 'SV-104297' do
  title 'Symantec ProxySG providing content filtering must continuously monitor outbound communications traffic crossing internal security boundaries for unusual/unauthorized activities or conditions.'
  desc 'If outbound communications traffic is not continuously monitored, hostile activity may not be detected and prevented. Output from application and traffic monitoring serves as input to continuous monitoring and incident response programs.

Internal monitoring includes the observation of events occurring on the network as they cross internal boundaries at managed interfaces such as web content filters. Depending on the type of ALG, organizations can monitor information systems by monitoring audit activities, application access patterns, characteristics of access, content filtering, or unauthorized exporting of information across boundaries. Unusual/unauthorized activities or conditions may include large file transfers, long-time persistent connections, unusual protocols and ports in use, and attempted communications with suspected malicious external addresses.'
  desc 'check', 'Determine what proxy services are enabled on the ProxySG.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Services >> Proxy Services.
3. Review each service specified in the list with the ProxySG administrator to verify that all remote access traffic has been accounted for.
4. Click Configuration >> Policy >> Visual Policy Manager >> Launch.
5. Click each layer and Verify that the "Source" and "Destination" fields for each rule are set to the organizationally defined sources and destinations.

If Symantec ProxySG providing content filtering does not continuously monitor outbound communications traffic crossing internal security boundaries for unusual/unauthorized activities or conditions, this is a finding.'
  desc 'fix', %q(Configure proxy services.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Services >> Proxy Services.
3. Review each service specified in the list with the ProxySG administrator to ensure that all remote access traffic has been accounted for and add any that are missing per the ProxySG Administration Guide, Chapter 7: Managing Proxy Services. 
4. Click Configuration >> Policy >> Visual Policy Manager >> Launch.
5. Click each layer and right-click the "Source" and "Destination" fields for each rule. Select "Set" and set each to the organizationally defined values in accordance with the site's SSP.)
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93529r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94343'
  tag rid: 'SV-104297r1_rule'
  tag stig_id: 'SYMP-AG-000650'
  tag gtitle: 'SRG-NET-000391-ALG-000140'
  tag fix_id: 'F-100459r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002662']
  tag nist: ['SI-4 (4) (b)']
end
