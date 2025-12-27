control 'SV-104277' do
  title 'Symantec ProxySG must allow incoming communications only from organization-defined authorized sources routed to organization-defined authorized destinations.'
  desc 'Unrestricted traffic may contain malicious traffic that poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Access control policies and access control lists implemented on devices that control the flow of network traffic (e.g., application-level firewalls and web content filters) ensure the flow of traffic is only allowed from authorized sources to authorized destinations. Networks with different levels of trust (e.g., the Internet or CDS) must be kept separate.'
  desc 'check', 'Determine what proxy services are enabled on the ProxySG.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Services >> Proxy Services.
3. Review each service specified in the list with the ProxySG administrator to verify that all remote access traffic has been accounted for.
4. Click Configuration >> Policy >> Visual Policy Manager >> Launch.
5. Click each layer and Verify that the "Source" and "Destination" fields for each rule are set to the organizationally defined sources and destinations.

If Symantec ProxySG allows incoming communications other than those from organization-defined authorized sources routed to organization-defined authorized destinations, this is a finding.'
  desc 'fix', %q(Configure proxy services.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Services >> Proxy Services.
3. Review each service specified in the list with the ProxySG administrator to ensure that all remote access traffic has been accounted for and add any that are missing per the ProxySG Administration Guide, Chapter 7: Managing Proxy Services.
4. Click Configuration >> Policy >> Visual Policy Manager >> Launch.
5. Click each layer and right-click the "Source" and "Destination" fields for each rule. Select "Set" and set each to the organizationally defined values in accordance with the site's SSP.)
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93509r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94323'
  tag rid: 'SV-104277r1_rule'
  tag stig_id: 'SYMP-AG-000550'
  tag gtitle: 'SRG-NET-000364-ALG-000122'
  tag fix_id: 'F-100439r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
