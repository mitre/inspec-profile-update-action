control 'SV-38784' do
  title 'A file integrity baseline must be created and maintained.'
  desc 'A file integrity baseline is a collection of file metadata which is to evaluate the integrity of the system. A minimal baseline must contain metadata for all device files, setuid files, setgid files, system libraries, system binaries, and system configuration files. The minimal metadata must consist of the mode, owner, group owner, and modification times. For regular files, metadata must also include file size and a cryptographic hash of the file’s contents.'
  desc 'check', 'Determine if a file integrity baseline, which includes cryptographic hashes, has been created and maintained for the system. If no file integrity baseline exists for the system, this is a finding. If the file integrity baseline contains no cryptographic hashes, this is a finding. If the file integrity baseline is not maintained (has not been updated to be consistent with the latest approved system configuration changes), this is a finding.'
  desc 'fix', 'Create a file integrity baseline, including cryptographic hashes, for the system. 

# find / -depth -print | tee Baseline

Open the above file and either manually execute md5sum, csum, or the chksum command on each file. Alternatively, write a script to perform the above. NOTE: For security purposes, "md5sum" is preferred over "chksum".  The md5sum command can be loaded from the Linux Tool Kit for AIX.  
Alternatively,   OpenSSL can be used to create hashes.
#openssl dgst -md5 < file >'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-7918r2_chk'
  tag severity: 'medium'
  tag gid: 'V-11941'
  tag rid: 'SV-38784r1_rule'
  tag stig_id: 'GEN000140'
  tag gtitle: 'GEN000140'
  tag fix_id: 'F-31619r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSW-1'
  tag cci: ['CCI-000293']
  tag nist: ['CM-2']
end
