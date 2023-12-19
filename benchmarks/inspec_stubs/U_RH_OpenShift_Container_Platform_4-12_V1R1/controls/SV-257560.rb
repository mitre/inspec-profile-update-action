control 'SV-257560' do
  title 'OpenShift must enforce access restrictions and support auditing of the enforcement actions.'
  desc "Enforcing access restrictions helps protect the OpenShift environment and its resources from unauthorized access, misuse, or malicious activities. By implementing access controls, OpenShift ensures that only authorized users or processes can access sensitive data, make changes to configurations, or perform privileged actions. This helps prevent unauthorized individuals or entities from compromising the system's security and integrity.

Enforcing access restrictions and auditing the enforcement actions ensures accountability for actions performed within the OpenShift environment. It helps identify the individuals or processes responsible for specific activities, whether they are legitimate actions or potential security breaches. This accountability discourages unauthorized or malicious behavior and supports incident response and forensic investigations.

Auditing the enforcement actions provides administrators with visibility into the system's security posture, access patterns, and potential security risks. It helps identify anomalies, detect suspicious activities, and monitor compliance with established security policies. This operational visibility enables timely detection and response to security incidents, ensuring the ongoing security and stability of the OpenShift environment.

"
  desc 'check', %q(Verify OpenShift is configured to audit the execution of the "execve" system call by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; grep -e "execpriv" /etc/audit/audit.rules' 2>/dev/null; done

Confirm the following rules exist on each node:

-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv

If the above rules are not listed on each node, this is a finding.)
  desc 'fix', 'Apply the machine config to audit the execution of "execve" by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 75-audit-rules-suid-privilege-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    storage:
      files:
      - contents:
          source: data:,-a%20always%2Cexit%20-F%20arch=b32%20-S%20execve%20-C%20uid%21=euid%20-F%20euid=0%20-k%20execpriv%0A-a%20always%2Cexit%20-F%20arch=b64%20-S%20execve%20-C%20uid%21=euid%20-F%20euid=0%20-k%20execpriv%0A-a%20always%2Cexit%20-F%20arch=b32%20-S%20execve%20-C%20gid%21=egid%20-F%20egid=0%20-k%20execpriv%0A-a%20always%2Cexit%20-F%20arch=b64%20-S%20execve%20-C%20gid%21=egid%20-F%20egid=0%20-k%20execpriv%0A
        mode: 0644
        path: /etc/audit/rules.d/75-audit-suid-privilege-function.rules
        overwrite: true
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61295r921621_chk'
  tag severity: 'medium'
  tag gid: 'V-257560'
  tag rid: 'SV-257560r921623_rule'
  tag stig_id: 'CNTR-OS-000720'
  tag gtitle: 'SRG-APP-000381-CTR-000905'
  tag fix_id: 'F-61219r921622_fix'
  tag satisfies: ['SRG-APP-000381-CTR-000905', 'SRG-APP-000343-CTR-000780']
  tag 'documentable'
  tag cci: ['CCI-001814', 'CCI-002234']
  tag nist: ['CM-5 (1)', 'AC-6 (9)']
end
