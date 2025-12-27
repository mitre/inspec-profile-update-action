control 'SV-257553' do
  title 'OpenShift must prevent kernel profiling.'
  desc 'Kernel profiling involves monitoring and analyzing the behavior of the kernel, including its internal operations and system calls. This level of access and visibility into the kernel can potentially be exploited by attackers to gather sensitive information or launch attacks. By preventing kernel profiling, the attack surface is minimized and the risk of unauthorized access or malicious activities targeting the kernel is reduced.

Kernel profiling can introduce additional overhead and resource utilization, potentially impacting the stability and performance of the system. Profiling tools and techniques often involve instrumenting the kernel code, injecting hooks, or collecting detailed data, which may interfere with the normal operation of the kernel. By disallowing kernel profiling, OpenShift helps ensure the stability and reliability of the platform, preventing any potential disruptions caused by profiling activities.'
  desc 'check', %q(Verify the Red Hat Enterprise Linux CoreOS (RHCOS) is configured to prevent kernel profiling by unprivileged users.

Check the status of the kernel.perf_event_paranoid kernel parameter by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; sysctl kernel.perf_event_paranoid
' 2>/dev/null; done

If "kernel.perf_event_paranoid" is not set to "2" or is missing, this is a finding.)
  desc 'fix', 'Apply the machine config to prevent kernel profiling by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 75-sysctl-kernel-perf-event-paranoid-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    storage:
      files:
      - contents:
          source: data:,kernel.perf_event_paranoid%3D2%0A
        mode: 0644
        path: /etc/sysctl.d/75-sysctl_kernel_perf_event_paranoid.conf
        overwrite: true
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61288r921600_chk'
  tag severity: 'medium'
  tag gid: 'V-257553'
  tag rid: 'SV-257553r921602_rule'
  tag stig_id: 'CNTR-OS-000610'
  tag gtitle: 'SRG-APP-000243-CTR-000600'
  tag fix_id: 'F-61212r921601_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
