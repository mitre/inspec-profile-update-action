control 'SV-252849' do
  title 'Rancher MCM must prohibit or restrict the use of protocols that transmit unencrypted authentication information or use flawed cryptographic algorithms for transmission.'
  desc 'The container platform and its components will adhere to NIST 800-52R2. To ensure that traffic coming through the ingress controller is re-encrypted internally, switch off port 80 on the service object and direct ingress traffic to port 443 over HTTPS.'
  desc 'check', 'Navigate to Triple Bar Symbol(Global) >>  <local cluster>.
From the kubectl shell (>_) execute:
kubectl get ingress -n cattle-system rancher -o yaml

verify:
spec:
  rules:
  - host: rancher.example.com < Caution-http://rancher.example.com > 
    http:
      paths:
      - backend:
          service:
            name: rancher
            port:
              number: 443

kubectl get svc rancher -n cattle-system -o yaml
Verify:
spec:
  clusterIP: 10.43.145.4
  clusterIPs:
  - 10.43.145.4
  ipFamilies:
  - IPv4
  ipFamilyPolicy: SingleStack
  ports:
  - name: https-internal
    port: 443
    protocol: TCP
    targetPort: 443

If the output does not match the above, this is a finding.'
  desc 'fix', %q(From the dropdown select Global >>  <local cluster>.
From the kubectl shell (>_) execute the following:

kubectl patch -n cattle-system service rancher -p '{"spec":{"ports":[{"port":443,"targetPort":443}]}}'
export RANCHER_HOSTNAME=rancher.disa-eval-2-6.tomatodamato.com < Caution-http://rancher.disa-eval-2-6.tomatodamato.com > 
kubectl -n cattle-system patch ingress rancher -p "{\"metadata\":{\"annotations\":{\"nginx.ingress.Kubernetes.io/backend-protocol\ < Caution-http://nginx.ingress.Kubernetes.io/backend-protocol\ > ":\"HTTPS\"}},\"spec\":{\"rules\":[{\"host\":\"$RANCHER_HOSTNAME\",\"http\":{\"paths\":[{\"backend\":{\"service\":{\"name\":\"rancher\",\"port\":{\"number\":443}}},\"pathType\":\"ImplementationSpecific\"}]}}]}}"
kubectl patch -n cattle-system service rancher --type=json -p '[{"op":"remove","path":"/spec/ports/0"}]')
  impact 0.7
  ref 'DPMS Target Rancher Government Solutions Multi-Cluster Manager'
  tag check_id: 'C-56305r819995_chk'
  tag severity: 'high'
  tag gid: 'V-252849'
  tag rid: 'SV-252849r819997_rule'
  tag stig_id: 'CNTR-RM-001730'
  tag gtitle: 'SRG-APP-000645-CTR-001410'
  tag fix_id: 'F-56255r819996_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
