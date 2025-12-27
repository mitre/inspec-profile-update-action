control 'SV-38271' do
  title 'A file integrity baseline including cryptographic hashes must be created and maintained.'
  desc 'A file integrity baseline is a collection of file metadata which is to evaluate the integrity of the system. A minimal baseline must contain metadata for all device files, setuid files, setgid files, system libraries, system binaries, and system configuration files. The minimal metadata must consist of the mode, owner, group owner, and modification times. For regular files, metadata must also include file size and a cryptographic hash of the file’s contents.'
  desc 'check', 'This will always be a manual review. Determine if a file integrity baseline, which includes cryptographic hashes, has been created and maintained for the system. While HPUX-HIDS has the ability to detect file system changes, it does not currently support the creation of a system baseline. A number of third-party vendors (TripWire, for example) may be used for this purpose. Additionally, local scripts may also be used to create and maintain the system baseline, though this would not be the preferred method.

Ask the SA if a file system baseline has been created and is being maintained on an ongoing basis.

If no file integrity baseline exists for the system, this is a finding. If the file integrity baseline contains no cryptographic hashes, this is a finding. If the file integrity baseline is not maintained (i.e., the baseline has not been updated to be consistent with the latest approved system configuration changes), this is a finding.'
  desc 'fix', 'Create a file integrity baseline, including cryptographic hashes, for the system. 

# find / -depth -print | tee HP11-v3_Baseline

Open the above file and either manually execute md5sum or the chksum command on each file. Alternatively, write a script to perform the above. NOTE: For security purposes, md5sum is preferred over chksum.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36231r2_chk'
  tag severity: 'medium'
  tag gid: 'V-11941'
  tag rid: 'SV-38271r1_rule'
  tag stig_id: 'GEN000140'
  tag gtitle: 'GEN000140'
  tag fix_id: 'F-31490r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSW-1'
  tag cci: ['CCI-000293']
  tag nist: ['CM-2']
end
