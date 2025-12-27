control 'SV-77749' do
  title 'The system must enable a persistent log location for all locally stored logs.'
  desc %q(ESXi can be configured to store log files on an in-memory file system.  This occurs when the host's "/scratch" directory is linked to "/tmp/scratch". When this is done only a single day's worth of logs are stored at any time. In addition log files will be reinitialized upon each reboot.  This presents a security risk as user activity logged on the host is only stored temporarily and will not persistent across reboots.  This can also complicate auditing and make it harder to monitor events and diagnose issues.  ESXi host logging should always be configured to a persistent datastore.

Note: Scratch space is configured automatically during installation or first boot of an ESXi host, and does not usually need to be manually configured. ESXi Installable creates a 4 GB Fat16 partition on the target device during installation if there is sufficient space, and if the device is considered Local.  If ESXi is installed on an SD card or USB device a persistent log location may not be configured upon install as normal.)
  desc 'check', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the Syslog.global.logDir value and verify it is set to a persistent location.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logDir

or

$esxcli = Get-EsxCli
$esxcli.system.syslog.config.get() | Select LocalLogOutput,LocalLogOutputIsPersistent

If the Syslog.global.logDir or LocalLogOutput value is not on persistent storage, this is a finding.

If the LocalLogOutputIsPersistent value is not true, this is a finding.'
  desc 'fix', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the Syslog.global.logDir value and set it to a known persistent location.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logDir | Set-AdvancedSetting -Value "New Log Location"'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63993r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63259'
  tag rid: 'SV-77749r1_rule'
  tag stig_id: 'ESXI-06-000045'
  tag gtitle: 'SRG-OS-000341-VMM-001220'
  tag fix_id: 'F-69177r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
