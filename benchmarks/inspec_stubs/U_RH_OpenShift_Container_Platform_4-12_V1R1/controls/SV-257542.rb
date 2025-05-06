control 'SV-257542' do
  title 'OpenShift must use FIPS-validated SHA-1 or higher hash function to provide replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

Anti-replay is a cryptographically based mechanism; thus, it must use FIPS-approved algorithms. An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. Note that the anti-replay service is implicit when data contains monotonically increasing sequence numbers and data integrity is assured. Use of DOD PKI is inherently compliant with this requirement for user and device access. Use of Transport Layer Security (TLS), including application protocols such as HTTPS and DNSSEC, that use TLS/SSL as the underlying security protocol is also complaint.

Configure the information system to use the hash message authentication code (HMAC) algorithm for authentication services to Kerberos, SSH, web management tool, and any other access method.'
  desc 'check', %q(Verify the authentication operator is configured to use a secure transport to an OpenIDConnect provider:

oc get oauth cluster -o jsonpath="{.spec.identityProviders[*]}{'\n'}"

If the transport is not secure (ex. HTTPS), this is a finding.)
  desc 'fix', 'Configure OpenShift to use an OpenIDConnect Identity Provider. Note: This STIG was written for OIC; do not use HTPasswd. Only use an approved identity provider.

Steps to configure OpenID provider:

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
      clientID: ... 
      clientSecret: 
        name: idp-secret
      claims: 
        preferredUsername:
        - preferred_username
        name:
        - name
        email:
        - email
      issuer: https://www.idp-issuer.com 
 
4. Apply OpenID config to cluster by executing the following:
 
oc apply -f ldapidp.yaml
 
Note: For more information on configuring an OpenID provider, refer to https://docs.openshift.com/container-platform/4.8/authentication/identity_providers/configuring-oidc-identity-provider.html.'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61277r921567_chk'
  tag severity: 'medium'
  tag gid: 'V-257542'
  tag rid: 'SV-257542r921569_rule'
  tag stig_id: 'CNTR-OS-000440'
  tag gtitle: 'SRG-APP-000156-CTR-000380'
  tag fix_id: 'F-61201r921568_fix'
  tag 'documentable'
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
