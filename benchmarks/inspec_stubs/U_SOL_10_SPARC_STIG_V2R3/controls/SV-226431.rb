control 'SV-226431' do
  title 'System security patches and updates must be installed and up-to-date.'
  desc 'Timely patching is critical for maintaining the operational availability, confidentiality, and integrity of Information Technology (IT) systems. However, failure to keep operating system and application software patched is a common mistake made by IT professionals. New patches are released daily, and it is often difficult for even experienced system administrators to keep abreast of all the new patches. When new weaknesses in an operating system exist, patches are usually made available by the vendor to resolve the problems. If the most recent security patches and updates are not installed, unauthorized users may take advantage of weaknesses present in the unpatched software. The lack of prompt attention to patching could result in a system compromise.'
  desc 'check', 'Use the smpatch(1m) utility to check for available security updates from Oracle.
# smpatch analyze
If there are security updates available, this is a finding.'
  desc 'fix', 'Apply available security updates from Oracle.
# smpatch update'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28592r482657_chk'
  tag severity: 'medium'
  tag gid: 'V-226431'
  tag rid: 'SV-226431r603265_rule'
  tag stig_id: 'GEN000120'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28580r482658_fix'
  tag 'documentable'
  tag legacy: ['SV-40813', 'V-783']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
