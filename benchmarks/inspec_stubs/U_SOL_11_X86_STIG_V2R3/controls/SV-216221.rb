control 'SV-216221' do
  title 'A file integrity baseline must be created, maintained, and reviewed on at least weekly to determine if unauthorized changes have been made to important system files located in the root file system.'
  desc "A file integrity baseline is a collection of file metadata which is to evaluate the integrity of the system. A minimal baseline must contain metadata for all device files, setuid files, setgid files, system libraries, system binaries, and system configuration files. The minimal metadata must consist of the mode, owner, group owner, and modification times. For regular files, metadata must also include file size and a cryptographic hash of the file's contents."
  desc 'check', 'The root role is required.

Solaris 11 includes the Basic Account and Reporting Tool (BART) which uses cryptographic-strength checksums and file system metadata to determine changes. By default, the manifest generator catalogs all attributes of all files in the root (/) file system. File systems mounted on the root file system are cataloged only if they are of the same type as the root file system.

A Baseline BART manifest may exist in: 
/var/adm/log/bartlogs/[control manifest filename]

If a BART manifest does not exist, this is a finding.

At least weekly, create a new BART baseline report.

# bart create > /var/adm/log/bartlogs/[new manifest filename]

Compare the new report to the previous report to identify any changes in the system baseline.

# bart compare /var/adm/log/bartlogs/[baseline manifest filename> /var/adm/log/bartlogs/[new manifest filename]

Examine the BART report for changes. If there are changes to system files in /etc that are not approved, this is a finding.'
  desc 'fix', 'The root role is required.

Solaris 11 includes the Basic Account and Reporting Tool (BART) which uses cryptographic-strength checksums and file system metadata to determine changes. By default, the manifest generator catalogs all attributes of all files in the root (/) file system. File systems mounted on the root file system are cataloged only if they are of the same type as the root file system.

Create a protected area to store BART manifests.
# mkdir /var/adm/log/bartlogs
# chmod 700 /var/adm/log/bartlogs

After initial installation and configuration of the system, create a manifest report of the current baseline.

# bart create > /var/adm/log/bartlogs/[baseline manifest filename]'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17459r373045_chk'
  tag severity: 'medium'
  tag gid: 'V-216221'
  tag rid: 'SV-216221r603268_rule'
  tag stig_id: 'SOL-11.1-090010'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17457r373046_fix'
  tag 'documentable'
  tag legacy: ['V-47987', 'SV-60859']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
