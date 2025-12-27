control 'SV-257507' do
  title 'OpenShift must use a centralized user management solution to support account management functions.'
  desc "OpenShift supports several different types of identity providers. To add users and grant access to OpenShift, an identity provider must be configured. Some of the identity provider types such as HTPassword only provide simple user management and are not intended for production. Other types are public services like GitHub. These provider types are not appropriate as they are managed by public service providers, and therefore are unable to enforce the organizations account management requirements.

Use either the LDAP or the OpenIDConnect Identity Provider type to configure OpenShift to use the organizations centrally managed IdP that is able to enforce the organization's policies regarding user identity management."
  desc 'check', %q(Verify the authentication operator is configured to use either an LDAP or a OpenIDConnect provider by executing the following:

oc get oauth cluster -o jsonpath="{.spec.identityProviders[*].type}{'\n'}"

If the output lists any other type besides LDAP or OpenID, this is a finding.)
  desc 'fix', 'Configure OpenShift to use an appropriate Identity Provider. Do not use HTPasswd. Use either LDAP(AD), OpenIDConnect, or an approved identity provider.

To configure LDAP provider:
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
 
To configure OpenID provider:
1. Create Secret for Client Secret by executing the following:
 
oc create secret generic idp-secret --from-literal=clientSecret=<secret> -n openshift-config
 
2. Create config map for OpenID Trust CA by executing the following:
 
oc create configmap ca-config-map --from-file=ca.crt=/path/to/ca -n openshift-config

3. Create OpenID Auth Config Resource YAML.
Using the preferred text editor, create a file named oidcidp.yaml using the example content (replacing config values as appropriate).

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
  tag check_id: 'C-61242r921462_chk'
  tag severity: 'medium'
  tag gid: 'V-257507'
  tag rid: 'SV-257507r921464_rule'
  tag stig_id: 'CNTR-OS-000030'
  tag gtitle: 'SRG-APP-000023-CTR-000055'
  tag fix_id: 'F-61166r921463_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
