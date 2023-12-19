control 'SV-217156' do
  title 'The SUSE operating system must disable the file system automounter unless required.'
  desc 'Automatically mounting file systems permits easy introduction of unknown devices, thereby facilitating malicious activity.

'
  desc 'check', 'Verify the SUSE operating system disables the ability to automount devices.

Check to see if automounter service is active with the following command:

# systemctl status autofs
autofs.service - Automounts filesystems on demand
Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled)
Active: inactive (dead)

If the "autofs" status is set to "active" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to disable the ability to automount devices.

Turn off the automount service with the following command:

# systemctl stop autofs
# systemctl disable autofs

If "autofs" is required for Network File System (NFS), it must be documented with the ISSO.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18384r369624_chk'
  tag severity: 'medium'
  tag gid: 'V-217156'
  tag rid: 'SV-217156r854092_rule'
  tag stig_id: 'SLES-12-010590'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-18382r369625_fix'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag legacy: ['V-77167', 'SV-91863']
  tag cci: ['CCI-000366', 'CCI-000778', 'CCI-001958']
  tag nist: ['CM-6 b', 'IA-3', 'IA-3']
end
