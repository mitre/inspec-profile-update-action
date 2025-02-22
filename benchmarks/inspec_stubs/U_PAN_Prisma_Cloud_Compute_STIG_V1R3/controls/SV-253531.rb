control 'SV-253531' do
  title 'Prisma Cloud Compute host compliance baseline policies must be set.'
  desc 'Consistent application of Prisma Cloud Compute compliance policies ensures the continual application of policies and the associated effects.

'
  desc 'check', %q(Navigate to Prisma Cloud Compute Console's >> Defend >> Compliance >> Hosts tab >> Running hosts tab.

If a "Default - alert on critical and high" rule does not exist, this is a finding. 

Check all the rules to verify the following Actions are not set to "Ignore". (Click "Rule name".)

<Filter on Rule ID>

ID = 8112 - Verify the --anonymous-auth argument is set to false (kube-apiserver) - master node.

ID = 8212 - Verify the --anonymous-auth argument is set to false (kubelet) - worker node.

ID = 8311 - Verify the --anonymous-auth argument is set to false (federation-apiserver). 

ID = 81427 - Verify the Kubernetes PKI directory and file ownership are set to root:root.

ID = 81428 - Verify the Kubernetes PKI certificate file permissions are set to 644 or more restrictive.

ID = 8214 - Verify the --client-ca-file argument is set as appropriate (kubelet).

ID = 8227 - Verify the certificate authorities file permissions are set to 644 or more restrictive (kubelet).

ID = 8115 - Verify the --kubelet-https argument is set to true (kube-apiserver).

ID = 8116 - Verify the --insecure-bind-address argument is not set (kube-apiserver).

ID = 8117 - Verify the --insecure-port argument is set to 0 (kube-apiserver) can determine if the Kubernetes API is configured to only listen on the TLS-enabled port (TCP 6443).

ID = 8118 - Verify the --secure-port argument is not set to 0 (kube-apiserver).

ID = 81122 - Verify the --kubelet-certificate-authority argument is set as appropriate (kube-apiserver).

ID = 81123 - Verify the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate (kube-apiserver).

ID = 81129 - Verify the --tls-cert-file and --tls-private-key-file arguments are set as appropriate (kube-apiserver).

ID = 82112 - Verify the --tls-cert-file and --tls-private-key-file arguments are set as appropriate (kubelet).

ID = 81141 - Verify the --authorization-mode argument includes RBAC (kube-apiserver).

If any of these checks are set to "Ignore", to all host nodes within the intended monitored environment, this is a finding.)
  desc 'fix', %q(Navigate to Prisma Cloud Compute Console's >> Defend >> Compliance >> Hosts tab >> Running hosts tab.

Add Rule:
- Click "Add rule".
  Name = "Default - alert on critical and high"
  Scope = "All"
- Change Action to the values shown below (Change Action).
- Accept the other defaults and click "Save".

Change Action:
- Click "Rule name".
<Filter on Rule ID>

ID = 8112 - Description (--anonymous-auth argument is set to false (kube-apiserver) - master node)
- Change Action to "Alert" or "Block" (based on organizational needs).
- Click "Save".

ID = 8212 - Description (--anonymous-auth argument is set to false (kubelet) - worker node)
- Change Action to "Alert" or "Block" (based on organizational needs).
- Click "Save".

ID = 8311 - Description (--anonymous-auth argument is set to false (federation-apiserver)).
- Change Action to "Alert" or "Block" (based on organizational needs).
- Click "Save".

ID = 81427 - Description (Kubernetes PKI directory and file ownership is set to root:root).
- Change Action to "Alert" or "Block" (based on organizational needs).
- Click "Save".

ID = 81428 - Description (Kubernetes PKI certificate file permissions are set to 644 or more restrictive).
- Change Action to "Alert" or "Block" (based on organizational needs).
- Click "Save".

ID = 8214 - Description (--client-ca-file argument is set as appropriate (kubelet)).
- Change Action to "Alert" or "Block" (based on organizational needs).
- Click "Save".

ID = 8227 - Description (certificate authorities file permissions are set to 644 or more restrictive (kubelet)).
- Change Action to "Alert" or "Block" (based on organizational needs).
- Click "Save".

ID = 8115 - Description (--kubelet-https argument is set to true (kube-apiserver))
- Change Action to "Alert" or "Block" (based on organizational needs).
- Click "Save".

ID = 8116 - Description (--insecure-bind-address argument is not set (kube-apiserver)).
- Change Action to "Alert" or "Block" (based on organizational needs).
- Click "Save".

ID = 8117 - Description (--insecure-port argument is set to 0 (kube-apiserver) can determine if the Kubernetes API is configured to only listen on the TLS enabled port (TCP 6443)).
- Change Action to "Alert" or "Block" (based on organizational needs).
- Click "Save".

ID = 8118 - Description (--secure-port argument is not set to 0 (kube-apiserver)).
- Change Action to "Alert" or "Block" (based on organizational needs).
- Click "Save".

ID = 81122 - Description (--kubelet-certificate-authority argument is set as appropriate (kube-apiserver)).
- Change Action to "Alert" or "Block" (based on organizational needs).
- Click "Save".

ID = 81123 - Description (--kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate (kube-apiserver)).
ID = 81129 - Description (--tls-cert-file and --tls-private-key-file arguments are set as appropriate (kube-apiserver)).
- Change Action to "Alert" or "Block" (based on organizational needs).
- Click "Save".

ID = 82112 - Description (--tls-cert-file and --tls-private-key-file arguments are set as appropriate (kubelet)).
- Change Action to "Alert" or "Block" (based on organizational needs).
- Click "Save".

ID = 81141 - Description (--authorization-mode argument includes RBAC (kube-apiserver)).
- Change Action to "Alert" or "Block" (based on organizational needs).
- Click "Save".)
  impact 0.7
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56983r840429_chk'
  tag severity: 'high'
  tag gid: 'V-253531'
  tag rid: 'SV-253531r879586_rule'
  tag stig_id: 'CNTR-PC-000430'
  tag gtitle: 'SRG-APP-000133-CTR-000295'
  tag fix_id: 'F-56934r840430_fix'
  tag satisfies: ['SRG-APP-000133-CTR-000295', 'SRG-APP-000133-CTR-000310', 'SRG-APP-000141-CTR-000315', 'SRG-APP-000384-CTR-000915']
  tag 'documentable'
  tag cci: ['CCI-000381', 'CCI-001499', 'CCI-001764']
  tag nist: ['CM-7 a', 'CM-5 (6)', 'CM-7 (2)']
end
