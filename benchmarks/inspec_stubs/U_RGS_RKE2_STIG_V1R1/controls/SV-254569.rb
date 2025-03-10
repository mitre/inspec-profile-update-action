control 'SV-254569' do
  title 'Rancher RKE2 runtime must isolate security functions from nonsecurity functions.'
  desc "RKE2 runs as isolated as possible.

RKE2 is a container-based Kubernetes distribution. A container image is essentially a complete and executable version of an application, which relies only on the host's OS kernel. Running containers use resource isolation features in the OS kernel, such as cgroups in Linux, to run multiple independent containers on the same OS. Unless part of the core RKE2 system or configured explicitly, containers managed by RKE2 should not have access to host resources.

Proper hardening of the surrounding environment is independent of RKE2 but ensures overall security stature.

When Kubernetes launches a container, there are several mechanisms available to ensure complete deployments:
- When a primary container process fails it is destroyed rebooted.
- When Liveness checks fail for the container deployment it is destroyed rebooted.
- If a readiness check fails at any point after the deployment the container is destroyed rebooted.
- Kubernetes has the ability to rollback a deployment configuration to a previous state if a deployment fails.
- Failover traffic to a working replica if any of the previous problems are encountered.

System kernel is responsible for memory, disk, and task management. The kernel provides a gateway between the system hardware and software. Kubernetes requires kernel access to allocate resources to the Control Plane. Threat actors that penetrate the system kernel can inject malicious code or hijack the Kubernetes architecture. It is vital to implement protections through Kubernetes components to reduce the attack surface."
  desc 'check', 'Ensure protect-kernel-defaults argument is set correctly.

Run this command on each node:
/bin/ps -ef | grep kubelet | grep -v grep

If --protect-kernel-defaults is not set to "true" or is not configured, this is a finding.'
  desc 'fix', 'Edit the Kubernetes Kubelet file etc/rancher/rke2/config.yaml on the RKE2 Control Plane and set the following:
 --protect-kernel-defaults=true

Once configuration file is updated, restart the RKE2 Agent. Run the command:
systemctl restart rke2-agent'
  impact 0.5
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58053r859275_chk'
  tag severity: 'medium'
  tag gid: 'V-254569'
  tag rid: 'SV-254569r859277_rule'
  tag stig_id: 'CNTR-R2-000940'
  tag gtitle: 'SRG-APP-000233-CTR-000585'
  tag fix_id: 'F-58002r859276_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
