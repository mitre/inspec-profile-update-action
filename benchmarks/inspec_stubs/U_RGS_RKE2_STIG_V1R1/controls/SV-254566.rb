control 'SV-254566' do
  title 'Rancher RKE2 runtime must enforce ports, protocols, and services that adhere to the PPSM CAL.'
  desc 'Ports, protocols, and services within the RKE2 runtime must be controlled and conform to the PPSM CAL. Those ports, protocols, and services that fall outside the PPSM CAL must be blocked by the runtime. Instructions on the PPSM can be found in DoD Instruction 8551.01 Policy.

RKE2 sets most ports and services configuration upon initiation, however, these ports can be changed after the fact to non-compliant configurations. It is important to verify core component configurations for compliance.

API Server, Scheduler, Controller, ETCD, and User Pods should all be checked to ensure proper PPS configuration.

'
  desc 'check', 'Check Ports, Protocols, and Services (PPS)
Change to the /var/lib/rancher/rke2/agent/ directory on the Kubernetes RKE2 Control Plane. 
Run the command:
grep kube-apiserver.manifest -I-insecure-port
grep kube-apiserver.manifest -I -secure-port
grep kube-apiserver.manifest -I -etcd-servers *

Review findings against the most recent PPSM CAL:
https://cyber.mil/ppsm/cal/

Any manifest and namespace PPS or services configuration not in compliance with PPSM CAL is a finding.

If there are any ports, protocols, and services in the system documentation not in compliance with the CAL PPSM, this is a finding. Any PPS not set in the system documentation is a finding.

Verify API Server network boundary with the PPS associated with the CAL Assurance Categories. Any PPS not in compliance with the CAL Assurance Category requirements is a finding.
Review findings against the most recent PPSM CAL:
https://cyber.mil/ppsm/cal/

Running these commands individually will show what ports are currently configured to be used by each of the core components. Inspect this output and ensure only proper ports are being utilized. If any ports not defined as the proper ports are being used, this is a finding.

/var/lib/rancher/rke2/bin/kubectl get po -n kube-system -l component=kube-controller-manager -o=jsonpath="{.items[*].spec.containers[*].command}"

/var/lib/rancher/rke2/bin/kubectl get po -n kube-system -l component=kube-scheduler -o=jsonpath="{.items[*].spec.containers[*].command}"

/var/lib/rancher/rke2/bin/kubectl get po -n kube-system -l component=kube-apiserver -o=jsonpath="{.items[*].spec.containers[*].command}" | grep tls-min-version

Verify user pods:
User pods will also need to be inspected to ensure compliance. This will need to be on a case by case basis.
cat /var/lib/rancher/rke2/server/db/etcd/config
If any ports not defined as the proper ports are being used, this is a finding.'
  desc 'fix', 'Review the documentation covering how to set these PPSs and update this configuration file:

 /etc/rancher/rke2/config.yaml

Once configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server'
  impact 0.5
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58050r859266_chk'
  tag severity: 'medium'
  tag gid: 'V-254566'
  tag rid: 'SV-254566r859268_rule'
  tag stig_id: 'CNTR-R2-000580'
  tag gtitle: 'SRG-APP-000142-CTR-000325'
  tag fix_id: 'F-57999r859267_fix'
  tag satisfies: ['SRG-APP-000142-CTR-000325', 'SRG-APP-000142-CTR-000330', 'SRG-APP-000383-CTR-000910']
  tag 'documentable'
  tag cci: ['CCI-000382', 'CCI-001762']
  tag nist: ['CM-7 b', 'CM-7 (1) (b)']
end
