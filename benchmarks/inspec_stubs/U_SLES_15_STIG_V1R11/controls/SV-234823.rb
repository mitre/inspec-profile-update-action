control 'SV-234823' do
  title 'The SUSE operating system must disable the file system automounter unless required.'
  desc 'Automatically mounting file systems permits easy introduction of unknown devices, thereby facilitating malicious activity.

'
  desc 'check', 'Verify the SUSE operating system disables the ability to automount devices.

Check to see if automounter service is active with the following command:

> systemctl status autofs
autofs.service - Automounts filesystems on demand
Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled)
Active: inactive (dead)

If the "autofs" status is set to "active" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to disable the ability to automount devices.

Turn off the automount service with the following command:

> systemctl stop autofs
> systemctl disable autofs

If "autofs" is required for Network File System (NFS), it must be documented with the ISSO.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38011r618738_chk'
  tag severity: 'medium'
  tag gid: 'V-234823'
  tag rid: 'SV-234823r854187_rule'
  tag stig_id: 'SLES-15-010240'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-37974r618739_fix'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163']
  tag 'documentable'
  tag cci: ['CCI-000778', 'CCI-001958']
  tag nist: ['IA-3', 'IA-3']
end
