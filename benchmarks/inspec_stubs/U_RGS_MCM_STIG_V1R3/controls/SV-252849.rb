control 'SV-252849' do
  title 'Rancher MCM must prohibit or restrict the use of protocols that transmit unencrypted authentication information or use flawed cryptographic algorithms for transmission.'
  desc 'The container platform and its components will adhere to NIST 800-52R2. To ensure that traffic coming through the ingress controller is re-encrypted internally, switch off port 80 on the service object and direct ingress traffic to port 443 over HTTPS.'
  desc 'check', 'Navigate to Triple Bar Symbol(Global) >> <local cluster>.
From the kubectl shell (>_) execute:
kubectl get ingress -n cattle-system rancher -o yaml

Verify the port number for Rancher is using "443", like the following:
  spec:
    rules:
    - host: rancher.rfed.us
      http:
        paths:
        - backend:
            service:
              name: rancher
              port:
                number: 443

From the kubectl shell (>_) execute:
kubectl get networkpolicies -n cattle-system

Verify networkpolicies exist and that they are only allowing traffic to port "444" of the Rancher pods, like the following:
NAME                               POD-SELECTOR   AGE
rancher-allow-https      app=rancher        10h
rancher-deny-ingress    app=rancher        10h

If the ingress output is not using port 443, or there are not network policies in place to only allow traffic to port 444, this is a finding.'
  desc 'fix', %q(Gather the current values of the Rancher deployment by running the following:

helm get values -n cattle-system rancher > /tmp/rancher-values.yaml

Create another values file to upgrade Rancher's ingress object for HTTPS. Add the following to "/tmp/rancher-ingress-values.yaml":

ingress:
  extraAnnotations:
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS" # If using NGINX ingress
    traefik.ingress.kubernetes.io/router.tls: "true" # If using Traefik ingress
  servicePort: 443

If using a different ingress controller than NGINX or Traefik, other annotations may need to be added to ensure the controller knows the Rancher backend is HTTPS.

Upgrade Rancher, referencing the two files created:

helm upgrade -n cattle-system -f /tmp/rancher-values.yaml -f /tmp/rancher-ingress-values.yaml rancher rancher-stable/rancher --version=CURRENT_RANCHER_VERSION

Once Rancher ingress has been updated and it has been verified that Rancher is still accessible, run the following command to create NetworkPolicies that will block all traffic to Rancher with the exception of HTTPS:

cat <<EOF | kubectl apply -f -
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: rancher-allow-https
  namespace: cattle-system
spec:
  podSelector:
    matchLabels:
      app: rancher
  ingress:
  - ports:
    - port: 444
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: rancher-deny-ingress
  namespace: cattle-system
spec:
  podSelector:
    matchLabels:
      app: rancher
  policyTypes:
  - Ingress
EOF)
  impact 0.7
  ref 'DPMS Target Rancher Government Solutions Multi-Cluster Manager'
  tag check_id: 'C-56305r918222_chk'
  tag severity: 'high'
  tag gid: 'V-252849'
  tag rid: 'SV-252849r918224_rule'
  tag stig_id: 'CNTR-RM-001730'
  tag gtitle: 'SRG-APP-000645-CTR-001410'
  tag fix_id: 'F-56255r918223_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
