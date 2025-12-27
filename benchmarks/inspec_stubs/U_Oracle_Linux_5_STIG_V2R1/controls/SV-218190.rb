control 'SV-218190' do
  title 'A file integrity baseline including cryptographic hashes must be created.'
  desc "A file integrity baseline is a collection of file metadata which is to evaluate the integrity of the system. A minimal baseline must contain metadata for all device files, setuid files, setgid files, system libraries, system binaries, and system configuration files. The minimal metadata must consist of the mode, owner, group owner, and modification times. For regular files, metadata must also include file size and a cryptographic hash of the file's contents."
  desc 'check', 'Verify a system integrity baseline exists.  The Advanced Intrusion Detection Environment (AIDE) tool is included with the operating system.  Other host intrusion detection system (HIDS) software is available but must be checked manually.

Procedure:
# grep DBDIR /etc/aide.conf

If /etc/aide.conf does not exist AIDE has not been installed. Unless another HIDS is used on the system, this is a finding.

Examine the response for "database" this indicates the location of the system integrity baseline database used as input to a comparison. 
# ls -la <DBDIR>

If no "database" file as defined in /etc/aide.conf exists a system integrity baseline has not been created, this is a finding.

Examine /etc/aide.conf to ensure some form of cryptographic hash (i.e., md5, rmd160, sha256) is used for files. In the default /etc/aide.conf the "NORMAL" or "LSPP" rules which are used for virtually all files DO include some form of cryptographic hash.

If the site has defined rules to replace the functionality provided by the default "NORMAL" and "LSPP" rules but DOES NOT include cryptographic hashes, this is a finding.

Otherwise, if any element used to define the "NORMAL" and "LSPP" rules has been modified resulting in cryptographic hashes not being used, this is a finding.

If any other modification to the default /etc/aide.conf file have been made resulting in rules which do not include cryptographic hashes on appropriate files, this is a finding.'
  desc 'fix', 'Use AIDE to create a file integrity baseline, including cryptographic hashes, for the system.

Configure the /etc/aide.conf file to ensure some form of cryptographic hash (e.g., md5, rmd160, sha256) is used for files. In the default /etc/aide.conf the "NORMAL" or "LSPP" rules which are used for virtually all files DO include some form of cryptographic hash.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19665r568507_chk'
  tag severity: 'medium'
  tag gid: 'V-218190'
  tag rid: 'SV-218190r603259_rule'
  tag stig_id: 'GEN000140-2'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-19663r568508_fix'
  tag 'documentable'
  tag legacy: ['V-27250', 'SV-63101']
  tag cci: ['CCI-000293', 'CCI-001744']
  tag nist: ['CM-2', 'CM-3 (5)']
end
