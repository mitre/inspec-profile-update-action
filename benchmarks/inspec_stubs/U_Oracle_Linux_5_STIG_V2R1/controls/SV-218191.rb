control 'SV-218191' do
  title 'A file integrity baseline including cryptographic hashes must be maintained.'
  desc "A file integrity baseline is a collection of file metadata which is to evaluate the integrity of the system. A minimal baseline must contain metadata for all device files, setuid files, setgid files, system libraries, system binaries, and system configuration files. The minimal metadata must consist of the mode, owner, group owner, and modification times. For regular files, metadata must also include file size and a cryptographic hash of the file's contents."
  desc 'check', 'Verify a system integrity baseline is maintained.  The baseline has been updated to be consistent with the latest approved system configuration changes.  The Advanced Intrusion Detection Environment (AIDE) tool is included with the operating system.  Other host intrusion detection system (HIDS) software is available but must be checked manually.

Procedure:
# grep DBDIR /etc/aide.conf

If /etc/aide.conf does not exist AIDE has not been installed. Unless another HIDS is used on the system, this is a finding.

Examine the response for "database" indicates the location of the system integrity baseline database used as input to a comparison. 
# ls -la <DBDIR>

If the no "database" file as defined in /etc/aide.conf a system integrity baseline has not been created, this is a finding.

Ask the SA when the last approved system configuration changes occurred. If the modification date of the AIDE database is prior to the last approved configuration change, this is a finding.'
  desc 'fix', 'Regularly rebuild the integrity baseline, including cryptographic hashes, for the system to be consistent with the latest approved system configuration.

Procedure:
After an approved modification to the system configuration has been made perform:

# aide -u
This will update the database.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19666r568510_chk'
  tag severity: 'medium'
  tag gid: 'V-218191'
  tag rid: 'SV-218191r603259_rule'
  tag stig_id: 'GEN000140-3'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-19664r568511_fix'
  tag 'documentable'
  tag legacy: ['V-27251', 'SV-63129']
  tag cci: ['CCI-000293', 'CCI-001744']
  tag nist: ['CM-2', 'CM-3 (5)']
end
