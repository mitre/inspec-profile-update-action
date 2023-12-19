control 'SV-257583' do
  title 'Red Hat Enterprise Linux CoreOS (RHCOS) must disable SSHD service.'
  desc 'Any direct remote access to the RHCOS nodes is not allowed. RHCOS is a single-purpose container operating system and is only supported as a component of the OpenShift Container Platform. Remote management of the RHCOS nodes is performed at the OpenShift Container Platform API level. 

Disabling the SSHD service reduces the attack surface and potential vulnerabilities associated with SSH access. SSH is a commonly targeted vector by malicious actors, and disabling the service eliminates the potential risks associated with unauthorized SSH access or exploitation of SSH-related vulnerabilities.

By disabling SSHD, OpenShift can restrict access to the platform to only authorized channels and protocols. This helps mitigate the risk of unauthorized access attempts and reduces the exposure to potential brute-force attacks or password-guessing attacks against SSH.

Disabling SSHD encourages the use of more secure and controlled access mechanisms, such as API-based access or secure remote management tools provided by OpenShift. These mechanisms offer better access control and auditing capabilities, allowing administrators to manage and monitor access to the platform more effectively.

'
  desc 'check', %q(Verify the SSHD service is inactive and disabled by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; systemctl is-enabled sshd.service; systemctl is-active sshd.service' 2>/dev/null; done 

If the SSHD service is either active or enabled this is a finding.)
  desc 'fix', 'Apply the machine config to disable SSHD service by executing following: 

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do 
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 80-sshd-service-disable-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    systemd:
      units:
      - name: sshd.service
        enabled: false
" | oc apply -f -
done'
  impact 0.7
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61318r921690_chk'
  tag severity: 'high'
  tag gid: 'V-257583'
  tag rid: 'SV-257583r921692_rule'
  tag stig_id: 'CNTR-OS-001010'
  tag gtitle: 'SRG-APP-000141-CTR-000315'
  tag fix_id: 'F-61242r921691_fix'
  tag satisfies: ['SRG-APP-000141-CTR-000315', 'SRG-APP-000185-CTR-000490']
  tag 'documentable'
  tag cci: ['CCI-000381', 'CCI-000877']
  tag nist: ['CM-7 a', 'MA-4 c']
end
