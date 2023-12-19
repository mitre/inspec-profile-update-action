control 'SV-257545' do
  title 'OpenShift must separate user functionality (including user interface services) from information system management functionality.'
  desc "Red Hat Enterprise Linux CoreOS (RHCOS) is a single-purpose container operating system. RHCOS is only supported as a component of the OpenShift Container Platform. Remote management of the RHCOS nodes is performed at the OpenShift Container Platform API level. 

Any direct access to the RHCOS nodes is unnecessary. RHCOS only has two user accounts defined, root(0) and core(1000). These are the only two user accounts that should exist on the RHCOS nodes. As any administrative access or actions are to be done through the OpenShift Container Platform's administrative APIs, direct logon access to the RHCOS host must be disabled."
  desc 'check', %q(Verify that root and core are the only user accounts on the nodes by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; cat /etc/passwd' 2>/dev/null; done

The output will look similar to:

<node_name> root:x:0:0:root:/root:/bin/bash
core:x:1000:1000:CoreOS Admin:/var/home/core:/bin/bash
containers:x:993:995:User for housing the sub ID range for containers:/var/home/containers:/sbin/nologin

If there are any user accounts in addition to root, containers, and core, this is a finding.

Verify the root and core users are set to disable password logon by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; grep -e "^root" -e "^core" /etc/shadow' 2>/dev/null; done

The output will look similar to:
<node_name>
root:*:18367:0:99999:7:::
core:*:18939:0:99999:7:::

If the password entry has anything other than '*', this is a finding.)
  desc 'fix', %q(Disable and remove passwords from root and core accounts by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'usermod -p "*" root; usermod -p "*" core' 2>/dev/null; done

Remove any additional user accounts from the nodes by executing the following:

oc debug node/<node> -- chroot /host /bin/bash -c 'userdel <user>')
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61280r921576_chk'
  tag severity: 'medium'
  tag gid: 'V-257545'
  tag rid: 'SV-257545r921578_rule'
  tag stig_id: 'CNTR-OS-000500'
  tag gtitle: 'SRG-APP-000211-CTR-000530'
  tag fix_id: 'F-61204r921577_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
