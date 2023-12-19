control 'SV-250653' do
  title 'Persistent logging for all ESXi hosts must be configured.'
  desc %q(ESXi can be configured to store log files on an in-memory file system. This occurs when the host's "/scratch" directory is linked to "/tmp/scratch". When this is done only a single day's worth of logs are stored at any time, in addition, log files will be reinitialized upon each reboot. This presents a security risk as user activity logged on the host is only stored temporarily and will not persistent across reboots. This can also complicate auditing and make it harder to monitor events and diagnose issues. ESXi host logging should always be configured to a persistent datastore.

Note: ESXi automatically creates a persistent 4 GB Fat16 scratch partition on the local target device during installation. If space is not available, ESXi will store temporary data on a space constrained ramdisk. As ramdisk data does not persist across reboots, log and core files will be lost. Syslog.global.logDir points to a location on a local or remote datastore (and path) where log files can be saved to. The format [DatastoreName] DirectoryName/Filename maps to /vmfs/volumes/DatastoreName/DirectoryName/Filename. The [DatastoreName] is case sensitive and if the specified DirectoryName does not exist, it will be created. If the datastore path field is blank, logs are stored in their default location.)
  desc 'check', 'In vSphere Client, select the host in the inventory panel. Click the Configuration tab, then click Advanced Settings under Software. Check that the Syslog.global.logDir points to a persistent location. The directory should be specified as [datastorename] path_to_file where the path is relative to the datastore. For example, [datastore1] /systemlogs.

If the Syslog.global.logDir field is empty or explicitly points to a scratch partition, make sure that the field ScratchConfig.CurrentScratchLocation shows a location on persistent storage. 

If the Syslog.global.logDir field entry is not located on persistent storage, this is a finding.

Re-enable Lockdown Mode on the host.'
  desc 'fix', %q(From the vSphere Client, select the ESXi hosts and click "Configuration >> Advanced Settings >> Syslog >> global" and specify a known, persistent datastore for 'Syslog.global.logDir'.)
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54088r798956_chk'
  tag severity: 'medium'
  tag gid: 'V-250653'
  tag rid: 'SV-250653r798958_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000132'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54042r798957_fix'
  tag 'documentable'
  tag legacy: ['V-39293', 'SV-51109']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
