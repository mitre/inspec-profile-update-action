control 'SV-254564' do
  title 'Configuration and authentication files for Rancher RKE2 must be protected.'
  desc 'There are various configuration files, logs, access credentials, and other files stored on the host filesystem that contain sensitive information. 

These files could potentially put at risk, along with other specific workloads and components:
- API server
- proxy
- scheduler
- controller
- etcd
- Kubernetes administrator account information
- audit log access, modification, and deletion
- application access, modification, and deletion
- container runtime files

If an attacker can gain access to these files, changes can be made to open vulnerabilities and bypass user authorizations inherent within Kubernetes with RBAC implemented. It is crucial to ensure user permissions are enforced down through to the operating system. Protecting file permissions will ensure that if a nonprivileged user gains access to the system they will still not be able to access protected information from the cluster API, cluster configuration, and sensitive cluster information. This control relies on the underlying operating system also having been properly configured to allow only least privileged access to perform required operations.

'
  desc 'check', 'File system permissions:
1. Ensure correct permissions of the files in /etc/rancher/rke2:
cd /etc/rancher/rke2
ls -l

all owners are root:root
all permissions are 0640

2. Ensure correct permissions of the files in /var/lib/rancher/rke2:
cd /var/lib/rancher/rke2
ls -l 

all owners are root:root

3. Ensure correct permissions of the files and directories in /var/lib/rancher/rke2/agent:
cd /var/lib/rancher/rke2/agent
ls -l

owners and group are root:root
File permissions set to 0640 for the following:
rke2controller.kubeconfig
kubelet.kubeconfig
kubeproxy.kubeconfig

Certificate file permissions set to 0600
client-ca.crt
client-kubelet.crt
client-kube-proxy.crt
client-rke2-controller.crt
server-ca.crt
serving-kubelet.crt

Key file permissions set to 0600
client-kubelet.key
serving-kubelet.key
client-rke2-controller.key
client-kube-proxy.key

The directory permissions to 0700 
pod-manifests
etc 

4. Ensure correct permissions of the files in /var/lib/rancher/rke2/bin
cd /var/lib/rancher/rke2/bin
ls -l

all owners are root:root
all files are 0750

5. Ensure correct permissions of the directory /var/lib/rancher/rke2/data
cd /var/lib/rancher/rke2
ls -l

all owners are root:root
permissions are 0750

6. Ensure correct permissions of each file in /var/lib/rancher/rke2/data 
cd /var/lib/rancher/rke2/data
ls -l

all owners are root:root
all files are 0640

7. Ensure correct permissions of /var/lib/rancher/rke2/server
cd /var/lib/rancher/rke2/server
ls -l 

all owners are root:root

The following directories are set to 0700
cred
db
tls 

The following directories are set to 0750
manifests 
logs 

The following file is set to 0600
token 

8. Ensure the RKE2 Server configuration file on all RKE2 Server hosts contain the following:
(cat /etc/rancher/rke2/config.yaml)
write-kubeconfig-mode: "0640"

If any of the permissions specified above do not match the required level then this is a finding.'
  desc 'fix', 'File system permissions:
1. Fix permissions of the files in /etc/rancher/rke2
cd /etc/rancher/rke2
chmod 0640 ./*
chown root:root ./*
ls -l

2. Fix permissions of the files in /var/lib/rancher/rke2
cd /var/lib/rancher/rke2
chown root:root ./*
ls -l 

3. Fix permissions of the files and directories in /var/lib/rancher/rke2/agent
cd /var/lib/rancher/rke2/agent
chown root:root ./*
chmod 0700 pod-manifests
chmod 0700 etc
find . -maxdepth 1 -type f -name "*.kubeconfig" -exec chmod 0640 {} \\;
find . -maxdepth 1 -type f -name "*.crt" -exec chmod 0600 {} \\;
find . -maxdepth 1 -type f -name "*.key" -exec chmod 0600 {} \\;
ls -l

4. Fix permissions of the files in /var/lib/rancher/rke2/bin
cd /var/lib/rancher/rke2/agent/bin
chown root:root ./*
chmod 0750 ./*
ls -l

5. Fix permissions directory of /var/lib/rancher/rke2/data
cd /var/lib/rancher/rke2/agent
chown root:root data
chmod 0750 data
ls -l

6. Fix permissions of files in /var/lib/rancher/rke2/data
cd /var/lib/rancher/rke2/data
chown root:root ./*
chmod 0640 ./*
ls -l

7. Fix permissions in /var/lib/rancher/rke2/server
cd /var/lib/rancher/rke2/server
chown root:root ./*
chmod 0700 cred
chmod 0700 db
chmod 0700 tls
chmod 0750 manifests
chmod 0750 logs
chmod 0600 token
ls -l

Edit the RKE2 Server configuration file on all RKE2 Server hosts, located at /etc/rancher/rke2/config.yaml, to contain the following:

write-kubeconfig-mode: "0640"

Once configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server'
  impact 0.5
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58048r859260_chk'
  tag severity: 'medium'
  tag gid: 'V-254564'
  tag rid: 'SV-254564r859262_rule'
  tag stig_id: 'CNTR-R2-000520'
  tag gtitle: 'SRG-APP-000133-CTR-000300'
  tag fix_id: 'F-57997r859261_fix'
  tag satisfies: ['SRG-APP-000133-CTR-000300', 'SRG-APP-000133-CTR-000295', 'SRG-APP-000133-CTR-000305', 'SRG-APP-000133-CTR-000310']
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
