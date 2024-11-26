control 'SV-79709' do
  title 'The DataPower Gateway providing user authentication intermediary services must restrict user authentication traffic to specific authentication server(s).'
  desc "User authentication can be used as part of the policy filtering rule sets. Some URLs or network resources can be restricted to authenticated users only. Users are prompted by the application or browser for credentials. Authentication service may be provided by the ALG as an intermediary for the application; however, the authentication credential must be stored in the site's directory services server.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., proxy capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management)."
  desc 'check', 'Verify that a DataPower service processing policy includes an appropriately configured AAA policy action.

For example, for a Multi-Protocol Gateway service, this may be accomplished as follows:

On the main Control Panel of the DataPower WebGUI, click on Multi-Protocol Gateway >> Open the existing target Multi-Protocol Gateway instance >> Click on the "..." to the right of the Multi-Protocol Gateway Policy dropdown list box to open its processing policy. Confirm that the rule in the processing policy includes an AAA action. 

Double click on the AAA action (on the rule line) >> Click on the "..." to the right of the selected AAA Policy to open it >> Confirm that the values configured on the Main, Identity extraction, Authentication (specific authentication server specified), and Resource extraction tabs are correct.

If any of the configuration conditions are not met, this is a finding.'
  desc 'fix', 'Through the configuration of the Authentication tab an authentication, authorization, and audit policy (AAA), the DataPower Gateway restricts user authentication traffic to specific authentication server(s).

An AAA (authentication, authorization, audit) policy identifies a set of resources and procedures that determine whether a requesting client is granted access to a specific service, file, or document. AAA policies are similar to filters that accept or deny a specific client request.

AAA policies support a wide range of authentication and authorization mechanisms. You can "mix and match" multiple authentication and authorization mechanisms in a single policy. For example, one AAA policy can use a single RADIUS server to provide authentication and authorization services. Another policy can authenticate with RADIUS, map RADIUS credentials to an LDAP group with an XML file, and authorize with LDAP.

POLICY CONFIGURATION

The AAA policy must be configured as follows:

In the DataPower WebGUI, navigate to Objects >> XML Processing >> AAA Policy >> Press “Add” to add a new policy >> On the Main tab, configure general policy parameters >> On the Identity extraction tab, define how to extract the claimed identity of the service requestor >> 
On the Authentication tab, define the specific external control server that will accomplish authentication (e.g., LDAP) >> On the Resource extraction tab, configure how DataPower should extract the requested resource from the request message.

POLICY IMPLEMENTATION

This defined AAA policy must then be associated with a DataPower service. For a Multi-Protocol Gateway service this may be accomplished as follows:

On the main Control Panel of the DataPower WebGUI, click on Multi-Protocol Gateway >> Add and name a Multi-Protocol Gateway instance >> Click on the "+" to the right of the Multi-Protocol Gateway Policy dropdown list box >> Name the policy >> Click "New Rule" to add a processing rule to this gateway (DataPower service) >> Click and drag the AAA icon down to the processing line to the right of the "=" >> Double-click the AAA icon on the line. 

In the AAA Policy dropdown, select the policy you configured above >> Click Done >> Click Apply Policy >> Close window >> On the Configure Multi-Protocol Gateway screen, click Apply >> Click Save Configuration (in the upper right corner of the screen).'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65847r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65219'
  tag rid: 'SV-79709r1_rule'
  tag stig_id: 'WSDP-AG-000039'
  tag gtitle: 'SRG-NET-000138-ALG-000089'
  tag fix_id: 'F-71159r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
