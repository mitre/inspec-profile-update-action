control 'SV-257532' do
  title 'OpenShift must protect pod log files from any type of unauthorized access by setting owner permissions.'
  desc 'Pod log files may contain sensitive information such as application data, user credentials, or system configurations. Unauthorized access to these log files can expose sensitive data to malicious actors. By setting owner permissions, OpenShift ensures that only authorized users or processes with the necessary privileges can access the pod log files, preserving the confidentiality of the logged information.'
  desc 'check', %q(Verify the permissions and ownership of files located under "/var/log/pods" that store the output of pods are set to protect from unauthorized access.

1. Verify the files are readable only by the owner by executing the following command:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; find /var/log/pods/ -type f \( -perm /022 -o -perm /044 \\)' 2>/dev/null; done

If any files are returned, this is a finding.

2. Verify files are group-owned by root and owned by root by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; find /var/log/pods/ -type f \! -user 0' 2>/dev/null; done

(Example output:
ip-10-0-150-1 root root)

If "root" is not returned as the owner, this is a finding.

If "root" is not returned as the group owner, this is a finding.)
  desc 'fix', %q(Change the permissions and ownership of files located under "/var/log/pods" to protect from unauthorized access.

1. Execute the following to set the output of pods readable only by the owner:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; find /var/log/pods/ -type f \( -perm /022 -o -perm /044 \\) | xargs -r chmod 600' 2>/dev/null; done

2. Execute the following to set the group and group-ownership to root for files that store the output of pods:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; find /var/log/pods/ -type f \! -user 0 | xargs -r chown root:root' 2>/dev/null; done)
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61267r921537_chk'
  tag severity: 'medium'
  tag gid: 'V-257532'
  tag rid: 'SV-257532r921539_rule'
  tag stig_id: 'CNTR-OS-000300'
  tag gtitle: 'SRG-APP-000118-CTR-000240'
  tag fix_id: 'F-61191r921538_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
