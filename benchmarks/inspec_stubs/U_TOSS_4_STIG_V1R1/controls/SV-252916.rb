control 'SV-252916' do
  title 'The TOSS file system automounter must be disabled unless required.'
  desc 'Automatically mounting file systems permits easy introduction of unknown devices, thereby facilitating malicious activity.'
  desc 'check', 'Verify the operating system disables the ability to automount devices.

Check to see if automounter service is active with the following command:

Note: If the autofs service is not installed, this requirement is Not Applicable.

$ sudo systemctl status autofs

autofs.service - Automounts filesystems on demand
Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled)
Active: inactive (dead)

If the "autofs" status is set to "active" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the operating system to disable the ability to automount devices.

Turn off the automount service with the following commands:

$ sudo systemctl stop autofs
$ sudo systemctl disable autofs

If "autofs" is required for Network File System (NFS), it must be documented with the ISSO.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56369r824070_chk'
  tag severity: 'medium'
  tag gid: 'V-252916'
  tag rid: 'SV-252916r824072_rule'
  tag stig_id: 'TOSS-04-010050'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-56319r824071_fix'
  tag 'documentable'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
