control 'SV-257551' do
  title 'OpenShift must set the sticky bit for world-writable directories.'
  desc "Removing world-writable permissions or setting the sticky bit helps enforce access control on directories within the OpenShift platform. World-writable permissions allow any user to modify or delete files within the directory, which can introduce security risks. By removing these permissions or setting the sticky bit, OpenShift restricts modifications to the directory's owner and prevents unauthorized or unintended changes by other users."
  desc 'check', %q(Verify that all world-writable directories have the sticky bit set. List any world-writeable directories that do not have the sticky bit set by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; find / -type d \( -perm -0002 -a ! -perm -1000 ! -path "/var/lib/containers/*" ! -path "/var/lib/kubelet/pods/*" ! -path "/sysroot/ostree/deploy/*" \\) -print 2>/dev/null' 2>/dev/null; done

If there are any directories listed in the results, this is a finding.)
  desc 'fix', "Fix the directory permissions, by either removing world-writeable permission, or setting the sticky bit by executing the following:

oc debug node/<node_name> -- chroot /host /bin/bash -c 'chmod XXXX <directory>'

where
  node_name: The name of the node to connect to (oc get node)
  XXXX:  Either 1777 (sticky bit) or 0755 (remove group and world write permission)
  <directory>: The directory on which to correct the permissions"
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61286r921594_chk'
  tag severity: 'medium'
  tag gid: 'V-257551'
  tag rid: 'SV-257551r921596_rule'
  tag stig_id: 'CNTR-OS-000590'
  tag gtitle: 'SRG-APP-000243-CTR-000600'
  tag fix_id: 'F-61210r921595_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
