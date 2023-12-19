control 'SV-44763' do
  title 'A file integrity baseline including cryptographic hashes must be created.'
  desc 'A file integrity baseline is a collection of file metadata which is to evaluate the integrity of the system. A minimal baseline must contain metadata for all device files, setuid files, setgid files, system libraries, system binaries, and system configuration files. The minimal metadata must consist of the mode, owner, group owner, and modification times. For regular files, metadata must also include file size and a cryptographic hash of the file’s contents.'
  desc 'check', 'Verify a system integrity baseline exists. The Advanced Intrusion Detection Environment (AIDE) is included in the distribution of SLES. Other host intrusion detection system (HIDS) software is available but must be checked manually.

Procedure:
# grep DB /etc/aide.conf

If /etc/aide.conf does not exist AIDE has not been installed. Unless another HIDS is used on the system, this is a finding.

Examine the response for "database".  This indicates the location of the system integrity baseline database used as input to a comparison. 
# ls -la <DBDIR>

If no "database" file as defined in /etc/aide.conf exists, a system integrity baseline has not been created.This is a finding.

Examine /etc/aide.conf to ensure some form of cryptographic hash (ie. md5,rmd160,sha256) are used for files. In the default /etc/aide.conf the "NORMAL" or "LSPP" rules which are used for virtually all files DO include some form of cryptographic hash.

If the site has defined rules to replace the functionality provided by the default "NORMAL" and "LSPP" rules but DOES NOT include cryptographic hashes, this is a finding.

Otherwise, if any element used to define the "NORMAL" and "LSPP" rules has been modified resulting in cryptographic hashes not being used, this is a finding.

If any other modification to the default /etc/aide.conf file have been made resulting in rules which do not include cryptographic hashes on appropriate files, this is a finding.'
  desc 'fix', 'Use AIDE to create a file integrity baseline, including cryptographic hashes, for the system. 

Configure the /etc/aide.conf file to ensure some form of cryptographic hash (e.g., md5,rmd160,sha256) is used for files. In the default /etc/aide.conf the "NORMAL" or "LSPP" rules which are used for virtually all files DO include some form of cryptographic hash.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42268r2_chk'
  tag severity: 'medium'
  tag gid: 'V-27250'
  tag rid: 'SV-44763r2_rule'
  tag stig_id: 'GEN000140-2'
  tag gtitle: 'GEN000140-2'
  tag fix_id: 'F-38213r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000293']
  tag nist: ['CM-2']
end
