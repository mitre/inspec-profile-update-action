control 'SV-257541' do
  title 'OpenShift must use multifactor authentication for network access to accounts.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged and nonprivileged functions is greatly increased.

Multifactor authentication requires using two or more factors to achieve authentication.

Factors include: 
(i) something a user knows (e.g., password/PIN); 
(ii) something a user has (e.g., cryptographic identification device, token); or 
(iii) something a user is (e.g., biometric).

A privileged account is defined as an information system account with authorizations of a privileged user.

A nonprivileged account is any information system account with authorizations of a nonprivileged user.

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet).

'
  desc 'check', %q(Verify the authentication operator is configured to use either an LDAP or a OpenIDConnect provider by executing the following:

oc get oauth cluster -o jsonpath="{.spec.identityProviders[*].type}{'\n'}"

If the output lists any other type besides LDAP or OpenID, this is a finding.)
  desc 'fix', 'Configure OpenShift to use an appropriate Identity Provider. Do not use HTPasswd. Use either LDAP(AD), OpenIDConnect, or an approved identity provider.

Steps to configure LDAP provider:

1. Create Secret for BIND DN password by executing the following:

oc create secret generic ldap-secret --from-literal=bindPassword=<secret> -n openshift-config 

2. Create config map for LDAP Trust CA by executing the following:
 
oc create configmap ca-config-map --from-file=ca.crt=/path/to/ca -n openshift-config

3. Create LDAP Auth Config Resource YAML:
Using the preferred text editor, create a file named ldapidp.yaml using the example content. (replacing config values as appropriate):
 
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
 
Steps to configure OpenID provider:

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
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61276r921564_chk'
  tag severity: 'medium'
  tag gid: 'V-257541'
  tag rid: 'SV-257541r921566_rule'
  tag stig_id: 'CNTR-OS-000430'
  tag gtitle: 'SRG-APP-000149-CTR-000355'
  tag fix_id: 'F-61200r921565_fix'
  tag satisfies: ['SRG-APP-000149-CTR-000355', 'SRG-APP-000150-CTR-000360']
  tag 'documentable'
  tag cci: ['CCI-000765', 'CCI-000766']
  tag nist: ['IA-2 (1)', 'IA-2 (2)']
end
