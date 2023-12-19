control 'SV-257543' do
  title 'OpenShift must use FIPS validated LDAP or OpenIDConnect.'
  desc 'Passwords need to be protected on entry, in transmission, during authentication, and when stored. If compromised at any of these security points, a nefarious user can use the password along with stolen user account information to gain access or to escalate privileges. The container platform may require account authentication during container platform tasks and before accessing container platform components (e.g., runtime, registry, and keystore).

During any user authentication, the container platform must use FIPS-validated SHA-2 or later protocol to protect the integrity of the password authentication process.

'
  desc 'check', %q(Verify the authentication operator is configured to use either an LDAP or a OpenIDConnect provider by executing the following:

oc get oauth cluster -o jsonpath="{.spec.identityProviders[*].type}{'\n'}"

If the output lists any other type besides LDAP or OpenID, this is a finding.)
  desc 'fix', 'Configure OpenShift to use an appropriate Identity Provider. Do not use HTPasswd. Use either LDAP(AD), OpenIDConnect or an approved identity provider.

To configure LDAP provider:

1. Create Secret for BIND DN password by executing the following:

oc create secret generic ldap-secret --from-literal=bindPassword=<secret> -n openshift-config 

2. Create config map for LDAP Trust CA by executing the following:
 
oc create configmap ca-config-map --from-file=ca.crt=/path/to/ca -n openshift-config

3. Create LDAP Auth Config Resource YAML:
Using the preferred text editor, create a file named ldapidp.yaml using the example content (replacing config values as appropriate).
 
apiVersion: config.openshift.io/v1
kind: OAuth
metadata:
  name: cluster
spec:
  identityProviders:
  - name: ldapidp 
    mappingMethod: claim 
    type: LDAP
    ldap:
      attributes:
        id: 
        - dn
        email: 
        - mail
        name: 
        - cn
        preferredUsername: 
        - uid
      bindDN: <"bindDN">
      bindPassword: 
        name: ldap-secret
      ca: 
        name: ca-config-map
      insecure: false 
      url: <URL> 

4. Apply LDAP config to cluster by executing the following:
 
oc apply -f ldapidp.yaml
 
Note: For more information on configuring an LDAP provider, refer to https://docs.openshift.com/container-platform/4.8/authentication/identity_providers/configuring-ldap-identity-provider.html.
 
To configure OpenID provider:
 
1. Create Secret for Client Secret by executing the following:
 
oc create secret generic idp-secret --from-literal=clientSecret=<secret> -n openshift-config
 
2. Create config map for OpenID Trust CA by executing the following:
 
oc create configmap ca-config-map --from-file=ca.crt=/path/to/ca -n openshift-config

3. Create OpenID Auth Config Resource YAML.
Using your preferred text editor, create a file named oidcidp.yaml using the example content (replacing config values as appropriate).

apiVersion: config.openshift.io/v1
kind: OAuth
metadata:
  name: cluster
spec:
  identityProviders:
  - name: oidcidp
    mappingMethod: claim
    type: OpenID
    openID:
      clientID: <clientID>
      clientSecret:
        name: oidc-idp-secret
      claims:
        preferredUsername:
        - preferred_username
        name:
        - name
        email:
        - email
      ca:
        name: ca-config-map
      issuer: <URL>
 
4. Apply OpenID config to cluster by executing the following:
 
oc apply -f ldapidp.yaml
 
Note: For more information on configuring an OpenID provider, refer to https://docs.openshift.com/container-platform/4.8/authentication/identity_providers/configuring-oidc-identity-provider.html.'
  impact 0.7
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61278r921570_chk'
  tag severity: 'high'
  tag gid: 'V-257543'
  tag rid: 'SV-257543r921572_rule'
  tag stig_id: 'CNTR-OS-000460'
  tag gtitle: 'SRG-APP-000172-CTR-000440'
  tag fix_id: 'F-61202r921571_fix'
  tag satisfies: ['SRG-APP-000172-CTR-000440', 'SRG-APP-000024-CTR-000060', 'SRG-APP-000025-CTR-000065', 'SRG-APP-000065-CTR-000115', 'SRG-APP-000151-CTR-000365', 'SRG-APP-000152-CTR-000370', 'SRG-APP-000157-CTR-000385', 'SRG-APP-000163-CTR-000395', 'SRG-APP-000164-CTR-000400', 'SRG-APP-000165-CTR-000405', 'SRG-APP-000166-CTR-000410', 'SRG-APP-000167-CTR-000415', 'SRG-APP-000168-CTR-000420', 'SRG-APP-000169-CTR-000425', 'SRG-APP-000170-CTR-000430', 'SRG-APP-000171-CTR-000435', 'SRG-APP-000173-CTR-000445', 'SRG-APP-000174-CTR-000450', 'SRG-APP-000177-CTR-000465', 'SRG-APP-000317-CTR-000735', 'SRG-APP-000318-CTR-000740', 'SRG-APP-000345-CTR-000785', 'SRG-APP-000391-CTR-000935', 'SRG-APP-000397-CTR-000955', 'SRG-APP-000401-CTR-000965', 'SRG-APP-000402-CTR-000970']
  tag 'documentable'
  tag cci: ['CCI-000016', 'CCI-000017', 'CCI-000044', 'CCI-000187', 'CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-000195', 'CCI-000196', 'CCI-000197', 'CCI-000198', 'CCI-000199', 'CCI-000200', 'CCI-000205', 'CCI-000767', 'CCI-000768', 'CCI-000795', 'CCI-001619', 'CCI-001942', 'CCI-001953', 'CCI-001991', 'CCI-002009', 'CCI-002041', 'CCI-002142', 'CCI-002145', 'CCI-002238']
  tag nist: ['AC-2 (2)', 'AC-2 (3) (d)', 'AC-7 a', 'IA-5 (2) (a) (2)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (b)', 'IA-5 (1) (c)', 'IA-5 (1) (c)', 'IA-5 (1) (d)', 'IA-5 (1) (d)', 'IA-5 (1) (e)', 'IA-5 (1) (a)', 'IA-2 (3)', 'IA-2 (4)', 'IA-4 e', 'IA-5 (1) (a)', 'IA-2 (9)', 'IA-2 (12)', 'IA-5 (2) (d)', 'IA-8 (1)', 'IA-5 (1) (f)', 'AC-2 (10)', 'AC-2 (11)', 'AC-7 b']
end
