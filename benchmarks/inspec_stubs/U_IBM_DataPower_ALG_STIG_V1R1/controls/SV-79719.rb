control 'SV-79719' do
  title 'The DataPower Gateway providing user authentication intermediary services must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Lack of authentication enables anyone to gain access to the network or possibly a network element that provides opportunity for intruders to compromise resources within the network infrastructure. By identifying and authenticating non-organizational users, their access to network resources can be restricted accordingly.

Non-organizational users will be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access. Authorization requires an individual account identifier that has been approved, assigned, and configured on an authentication server. Authentication of user identities is accomplished through the use of passwords, tokens, biometrics, or in the case of multifactor authentication, some combination thereof.

This control applies to application layer gateways that provide content filtering and proxy services on network segments (e.g., DMZ) that allow access by non-organizational users. This requirement focuses on authentication requests to the proxied application for access to destination resources and policy filtering decisions rather than administrator and management functions.'
  desc 'check', 'Verify that a DataPower service processing policy includes an appropriately configured AAA policy action. For example, for a Multi-Protocol Gateway service, this may be accomplished as follows:

On the main Control Panel of the DataPower WebGUI, click on Multi-Protocol Gateway >> Open the existing target Multi-Protocol Gateway instance >> Click on the "..." to the right of the Multi-Protocol Gateway Policy dropdown list box to open its processing policy >> Confirm that the rule in the processing policy includes an AAA action >> Double-click on the AAA action (on the rule line) >> Click on the "..." to the right of the selected AAA Policy to open it >> Confirm that the values configured on the Main, Identity extraction, Authentication, and Resource extraction tabs are correct >> If any of the configuration conditions are not met, this is a finding.'
  desc 'fix', 'Through the configuration of an authentication, authorization, and audit policy (AAA), the DataPower Gateway provides user authentication intermediary services that uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).

POLICY CONFIGURATION

The AAA policy must be configured as follows:

In the DataPower WebGUI, navigate to Objects >> XML Processing >> AAA Policy. Press Add to add a new policy. 

On the Main tab, configure general policy parameters. 

On the Identity extraction tab, define how to extract the claimed identity of the service requestor. 

On the Authentication tab, define the specific external control server that will accomplish authentication (e.g., LDAP). 

On the Resource extraction tab, configure how DataPower should extract the requested resource from the request message.

POLICY IMPLEMENTATION

This defined AAA policy must then be associated with a DataPower service. For a Multi-Protocol Gateway service, this may be accomplished as follows:

On the main Control Panel of the DataPower WebGUI, click on Multi-Protocol Gateway >> Add and name a Multi-Protocol Gateway instance >> Click on the "+" to the right of the Multi-Protocol Gateway Policy dropdown list box >> Name the policy >> Click "New Rule" to add a processing rule to this gateway (DataPower service) >> Click and drag the AAA icon down to the processing line to the right of the "=" >> Double-click the AAA icon on the line >> In the AAA Policy dropdown, select the policy you configured above, then click Done >> Click Apply Policy >> Close window. 

On the Configure Multi-Protocol Gateway screen, click Apply, then Save Configuration (in the upper right corner of the screen.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65857r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65229'
  tag rid: 'SV-79719r1_rule'
  tag stig_id: 'WSDP-AG-000044'
  tag gtitle: 'SRG-NET-000169-ALG-000102'
  tag fix_id: 'F-71169r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
