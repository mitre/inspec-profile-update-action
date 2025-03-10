control 'SV-252848' do
  title 'Rancher MCM must enforce organization-defined circumstances and/or usage conditions for organization-defined accounts.'
  desc "Rancher MCM must verify the certificate used for Rancher's ingress is a valid DOD certificate. This is achieved by verifying the helm installation contains correct parameters."
  desc 'check', %q(Verify helm installation contains correct parameters:
Navigate to Triple Bar Symbol(Global) >>  <local cluster>.
From the kubectl shell (>_) Execute:
`helm get values rancher -n cattle-system`

The output must contain:
```
privateCA: true
ingress:
tls:
source: secret
```
If the output source is not "secret", this is a finding.

Verify contents of certificates are correct: 
From the console, type:
kubectl -n cattle-system get secret tls-rancher-ingress -o 'jsonpath={.data.tls\.crt}' | base64 --decode | openssl x509 -noout -text

kubectl -n cattle-system get secret tls-ca -o 'jsonpath={.data.cacerts\.pem}' | base64 --decode | openssl x509 -noout -text)
  desc 'fix', 'Update the secrets to contain valid certificates.

Put the correct and valid DOD certificate and key in files called "tls.crt" and "tls.key", respectively, and then run:
kubectl -n cattle-system create secret tls tls-rancher-ingress \\  --cert=tls.crt \\   --key=tls.key                         

Upload the CA required for the certs by creating another file called "cacerts.pem" and running: 
kubectl -n cattle-system create secret generic tls-ca \\   --from-file=cacerts.pem=./cacerts.pem 

The helm chart values need to be updated to include the check section: 
privateCA: true   
ingress:            
tls:                                                                        
source: secret   

Re-run helm upgrade with the new values for the certs to take effect.'
  impact 0.5
  ref 'DPMS Target Rancher Government Solutions Multi-Cluster Manager'
  tag check_id: 'C-56304r819992_chk'
  tag severity: 'medium'
  tag gid: 'V-252848'
  tag rid: 'SV-252848r819994_rule'
  tag stig_id: 'CNTR-RM-000970'
  tag gtitle: 'SRG-APP-000318-CTR-000740'
  tag fix_id: 'F-56254r819993_fix'
  tag 'documentable'
  tag cci: ['CCI-002145']
  tag nist: ['AC-2 (11)']
end
