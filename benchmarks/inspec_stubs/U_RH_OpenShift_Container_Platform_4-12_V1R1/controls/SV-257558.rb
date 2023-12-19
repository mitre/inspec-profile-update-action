control 'SV-257558' do
  title "Red Hat Enterprise Linux CoreOS (RHCOS) must allocate audit record storage capacity to store at least one weeks' worth of audit records, when audit records are not immediately sent to a central audit record storage facility."
  desc 'To ensure RHCOS has a sufficient storage capacity in which to write the audit logs, operating systems need to be able to allocate audit record storage capacity. The task of allocating audit record storage capacity is performed during initial installation of the operating system.'
  desc 'check', %q(Verify RHCOS allocates audit record storage capacity to store at least one week of audit records when audit records are not immediately sent to a central audit record storage facility.

Check the size of the partition to which audit records are written (with the example being /var/log/audit/) by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME ";  df -h /var/log/audit/' 2>/dev/null; done

<node> Filesystem      Size  Used Avail Use% Mounted on
/dev/sdb4       1.0T   27G  998G   3% /var

If the audit record partition is not allocated for sufficient storage capacity, this is a finding.

Note: The partition size needed to capture a week of audit records is based on the activity level of the system and the total storage capacity available. Typically, 10.0 GB of storage space for audit records should be sufficient. If the partition used is not exclusively for audit logs, then determine the amount of additional space needed to support the partition reserving enough space for audit logs.)
  desc 'fix', 'Reinstall the cluster, generating custom ignition configs to allocate audit record storage capacity.

1. Generate manifest files for the cluster by executing the following:

openshift-install create manifests --dir <install_dir>

2. Create a Butane config that configures additional partition by executing the following:

variant: openshift
version: 4.9.0
metadata:
  labels:
    machineconfiguration.openshift.io/role: worker
  name: 98-var-partition
storage:
  disks:
  - device: /dev/<device_name> 
    partitions:
    - label: var
      start_mib: <partition_start_offset> 
      size_mib: <partition_size> 
  filesystems:
    - device: /dev/disk/by-partlabel/var
      path: /var
      format: xfs
      mount_options: [rw, nodev, nosuid, noexec,...] 
      with_mount_unit: true

3. Create a manifest from the Butane config by executing the following:

butane <install_dir>/98-var-partition.bu -o <install_dir>/openshift/98-var-partition.yaml

4. Create the ignition config files by executing the following:

openshift-install create ignition-configs --dir <install_dir>'
  impact 0.3
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61293r921615_chk'
  tag severity: 'low'
  tag gid: 'V-257558'
  tag rid: 'SV-257558r921617_rule'
  tag stig_id: 'CNTR-OS-000670'
  tag gtitle: 'SRG-APP-000357-CTR-000800'
  tag fix_id: 'F-61217r921616_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
