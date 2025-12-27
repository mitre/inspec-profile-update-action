control 'SV-79717' do
  title 'The DataPower Gateway providing PKI-based user authentication intermediary services must map authenticated identities to the user account.'
  desc 'Authorization for access to any network element requires an approved and assigned individual account identifier. To ensure only the assigned individual is using the account, the account must be bound to a user certificate when PKI-based authentication is implemented.

This requirement applies to ALGs that provide user authentication intermediary services (e.g., authentication gateway or TLS gateway). This does not apply to authentication for the purpose of configuring the device itself (device management).'
  desc 'check', 'Verify that a DataPower service processing policy includes an appropriately configured AAA policy action.

For example, for a Multi-Protocol Gateway service, this may be accomplished as follows:

On the main Control Panel of the DataPower WebGUI, click on Multi-Protocol Gateway >> Open the existing target Multi-Protocol Gateway instance >> Click on the "..." to the right of the Multi-Protocol Gateway Policy dropdown list box to open its processing policy >> Confirm that the rule in the processing policy includes an AAA action >> Double click on the AAA action (on the rule line) >> Click on the "..." to the right of the selected AAA Policy to open it >> Review the values configured on the Main, Identity extraction, Authentication, Resource extraction, and Credential mapping tabs 

If any of the configuration conditions are not met, this is a finding.'
  desc 'fix', 'The AAA policy must be configured as follows:

In the DataPower WebGUI, navigate to Objects >> XML Processing >> AAA Policy >> Press Add to add a new policy.

On the Main tab, configure general policy parameters.

On the Identity extraction tab, select either of the following methods to extract the claimed identity of the service requestor: Subject DN of SSL certificate from connection peer or Subject DN from certificate in message signature.

On the Authentication tab, define the external control server that will accomplish authentication. 

On the Resource extraction tab, configure how DataPower should extract the requested resource from the request message. 

On the Credential mapping tab, select from the following options the desired method for credential mapping: Custom (Identifies a custom mapping resource such as a stylesheet or GatewayScript file), AAA information file (Identifies a DataPower information file, which is an XML file, as the mapping resource), Apply XPath expression (Identifies an XPath expression as the mapping resource), Credentials from WS-SecureConversation token (Identifies that credentials are taken from the WS-SecureConversation context token), Credentials from Tivoli Federated Identity Manager (Identifies that credentials are from a Tivoli Federated Identity Manager endpoint).

POLICY IMPLEMENTATION

This defined AAA policy must then be associated with a DataPower service. For example, using the Multi-Protocol Gateway service this may be accomplished as follows:

On the main Control Panel of the DataPower WebGUI, click on Multi-Protocol Gateway >> Add and name a Multi-Protocol Gateway instance >> Click on the "+" to the right of the Multi-Protocol Gateway Policy dropdown list box >> Name the policy >> Click "New Rule" to add a processing rule to this gateway (DataPower service) >> Click and drag the AAA icon down to the processing line to the right of the "=" >> Double click the AAA icon on the line >> In the AAA Policy dropdown, select the policy you configured above then click Done >> Click Apply Policy >> Close window.

On the Configure Multi-Protocol Gateway screen, click Apply, then Save Configuration (in the upper right corner of the screen.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65855r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65227'
  tag rid: 'SV-79717r1_rule'
  tag stig_id: 'WSDP-AG-000043'
  tag gtitle: 'SRG-NET-000166-ALG-000101'
  tag fix_id: 'F-71167r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
