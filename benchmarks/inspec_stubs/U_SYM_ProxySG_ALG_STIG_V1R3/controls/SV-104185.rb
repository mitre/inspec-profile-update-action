control 'SV-104185' do
  title 'Symantec ProxySG must enforce approved authorizations for controlling the flow of information within the network based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc 'Information flow control regulates where information is allowed to travel within a network. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data.

Information flow control policies and enforcement mechanisms are commonly employed by organizations to control the flow of information between designated sources and destinations (e.g., networks, individuals, devices) within information systems. Examples of information flow control restrictions include keeping export-controlled information from being transmitted in the clear to the Internet or blocking information marked as classified that is being transported to an unapproved destination.

ALGs enforce approved authorizations by employing security policy and/or rules that restrict information system services or provide packet filtering capability based on header or protocol information and/or message filtering capability based on data content (e.g., implementing keyword searches or using document characteristics).'
  desc 'check', %q(Obtain the SSP with the site's security policy. Verify that identity-based, role-based, and/or attribute-based authorization is configured for access to proxied websites. Verify that security policies and rules are configured and applied.

1. Log on to the web Management Console. 
2. Click Configuration >> Visual Policy Manager. 
3. Click "Launch". 
4. For each rule within each Web Access Layer, verify that the "Source" column for each rule contains something other than "any" (any is the default value). Rules must be verified as being compliant with the site's security policy.

If Symantec ProxySG does not enforce approved authorizations for controlling the flow of information within the network based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic, this is a finding.)
  desc 'fix', %q(Obtain the SSP with the site's security policy. Configure the ProxySG to enforce approved authorizations by employing identity-based, role-based, and/or attribute-based authorization for access to proxied websites.

1. Log on to the web Management Console.
2. Click Configuration >> Visual Policy Manager. 
3. Click "Launch". 
4. For each Web Access Layer that is configured, right-click the "Source" of each column and click "Set".
5. Select objects based on traffic attributes, content, source, or headers as required by the site's security policy.
6. For each Web Access Layer that is configured, right-click the "Destination" of each column and click "Set".
7. Select objects based on traffic attributes, content, destination, or headers as required by the site's security policy.
8. Click File >> Install Policy on SG Appliance.)
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93417r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94231'
  tag rid: 'SV-104185r1_rule'
  tag stig_id: 'SYMP-AG-000080'
  tag gtitle: 'SRG-NET-000018-ALG-000017'
  tag fix_id: 'F-100347r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
