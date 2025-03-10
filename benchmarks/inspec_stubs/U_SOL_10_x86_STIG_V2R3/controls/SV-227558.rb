control 'SV-227558' do
  title 'A file integrity baseline must be created and maintained.'
  desc "A file integrity baseline is a collection of file metadata which is to evaluate the integrity of the system. A minimal baseline must contain metadata for all device files, setuid files, setgid files, system libraries, system binaries, and system configuration files. The minimal metadata must consist of the mode, owner, group owner, and modification times. For regular files, metadata must also include file size and a cryptographic hash of the file's contents."
  desc 'check', 'Determine if a file integrity baseline, which includes cryptographic hashes, has been created and maintained for the system. If no file integrity baseline exists for the system, this is a finding. If the file integrity baseline contains no cryptographic hashes, this is a finding. If the file integrity baseline is not maintained (has not been updated to be consistent with the latest approved system configuration changes), this is a finding.'
  desc 'fix', 'Create a file integrity baseline, including cryptographic hashes, for the system.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36437r602914_chk'
  tag severity: 'medium'
  tag gid: 'V-227558'
  tag rid: 'SV-227558r854462_rule'
  tag stig_id: 'GEN000140'
  tag gtitle: 'SRG-OS-000363'
  tag fix_id: 'F-36401r602915_fix'
  tag 'documentable'
  tag legacy: ['V-11941', 'SV-12442']
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
