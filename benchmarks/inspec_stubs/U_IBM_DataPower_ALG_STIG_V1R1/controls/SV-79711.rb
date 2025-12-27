control 'SV-79711' do
  title 'The DataPower Gateway providing user authentication intermediary services must use multifactor authentication for network access to non-privileged accounts.'
  desc 'To assure accountability and prevent unauthenticated access, non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system.

Multifactor authentication uses two or more factors to achieve authentication. Factors include: 

1) Something you know (e.g., password/PIN), 
2) Something you have (e.g., cryptographic, identification device, token), and 
3) Something you are (e.g., biometric)

Non-privileged accounts are not authorized access to the network element regardless of access method.

Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.

Authenticating with a PKI credential and entering the associated PIN is an example of multifactor authentication.

This requirement applies to ALGs that provide user authentication intermediary services.'
  desc 'check', 'Scenario 1:
Prerequisites:

1. The user’s identity/attributes are stored in LDAP, including Distinguished Name (DN) and DataPower group membership (users can only be a member of one group).

2. The user has a device that has access to their digital certificate (e.g., via a CAC/PIV card reader connected to a laptop/desktop computer). The user opens a browser and navigates to the URL for the DataPower WebGUI. The user provides their assigned ID and password, which are authenticated by DataPower.

If the user does not gain access to the DataPower appliance Control Panel screen, this is a finding.

Scenario 2:
Prerequisites:

1. The user’s identity/attributes are stored in LDAP, including Distinguished Name (DN) and DataPower group membership (users can only be a member of one group).

2. The user has a device that has access to a different user’s digital certificate (e.g., via a CAC/PIV card reader connected to a laptop/desktop computer). The user opens a browser and navigates to the URL for the DataPower WebGUI. The user provides their assigned ID and password, which are authenticated by DataPower.

If the user gains access to the DataPower appliance Control Panel screen, this is a finding.

Scenario 3:
Prerequisites:

1. The user’s identity/attributes are stored in LDAP, including Distinguished Name (DN). In this case, the DataPower group membership is either not defined, or a group name is specified for which there is no corresponding group definition on the DataPower appliance.

2. The user has a device that has access to a different user’s digital certificate (e.g., via a CAC/PIV card reader connected to a laptop/desktop computer). The user opens a browser and navigates to the URL for the DataPower WebGUI. The user provides their assigned ID and password, which are authenticated by DataPower.

If the user gains access to the DataPower appliance Control Panel screen, this is a finding.'
  desc 'fix', 'This scenarios starts with a user connecting to DataPower over an HTTPS connection in which the user is providing a digital certificate that asserts their identity. This digital certificate could come from a CAC/PIV/Smart Card, or could be a “soft-certificate” embedded into a browser/application on a desktop, laptop, or mobile device.

All configuration tasks take place within the default domain.

DataPower’s WebGUI interface configuration is configured to require a client-supplied digital certificate: Network >> Management >> Web Management Service >> Advanced Tab >> Custom SSL Server Type: “Server Profile” >> Custom SSL Server Profile >> Click “+” >> Provide a name for the profile >> Configure “Identity Credentials” >> Request Client Authentication: “on” >> Configure “validation credentials” (used to validate the client’s digital certificate using Certificate Authority (CA) signer certificates). 

When configuring the Validation Credentials, configure Use CRL: “on”; Require CRL: “on”. CRL Retrieval is configured via Objects >> Crypto Configuration >> CRL Retrieval >> Advanced Tab >> Configure CRL retrieval policies.

Once an SSL connection is established to the WebGUI, the user is promoted for an ID and password. Authentication for all DataPower users is configured via the Role Based Management (RBM) feature: Administration >> Access >> RBM Settings. 

Configure “Authentication (Authentication Tab) >> Authentication Method >> Custom >> Custom URL (URL referencing an XSL Stylesheet or GatewayScript file on the appliance). 

The XSL/GatewayScript will receive an XML node at runtime containing the user’s ID and password, as submitted via the WebGUI logon page. The script will need to authenticate the ID/Password credentials using an LDAP/AD server. Once the user has been authenticated via ID/Password, the LDAP record for the user is retrieved including the Distinguished Name (DN) and DataPower group membership. A given user can only be assigned to single DataPower group. The user’s DN from LDAP is compared to the DN that the XSLT/script extracts from the SSL Client Certificate. If the two DN values match, then the user is considered to have authenticated with two factors.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65849r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65221'
  tag rid: 'SV-79711r1_rule'
  tag stig_id: 'WSDP-AG-000040'
  tag gtitle: 'SRG-NET-000140-ALG-000094'
  tag fix_id: 'F-71161r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
