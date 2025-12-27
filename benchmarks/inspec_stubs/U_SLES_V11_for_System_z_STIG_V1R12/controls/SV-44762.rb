control 'SV-44762' do
  title 'System security patches and updates must be installed and up-to-date.'
  desc 'Timely patching is critical for maintaining the operational availability, confidentiality, and integrity of information technology (IT) systems. However, failure to keep operating system and application software patched is a common mistake made by IT professionals. New patches are released daily, and it is often difficult for even experienced system administrators to keep abreast of all the new patches. When new weaknesses in an operating system exist, patches are usually made available by the vendor to resolve the problems. If the most recent security patches and updates are not installed, unauthorized users may take advantage of weaknesses present in the unpatched software. The lack of prompt attention to patching could result in a system compromise.'
  desc 'check', 'Obtain the list of available package security updates from Novell. Check the available package updates have been installed on the system.

Use the "rpm" command to list the packages installed on the system.
Example:
# rpm -qa --last

If updated packages are available and applicable to the system and have not been installed, this is a finding.'
  desc 'fix', 'Install the security patches or updated packages available from the vendor.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42267r3_chk'
  tag severity: 'medium'
  tag gid: 'V-783'
  tag rid: 'SV-44762r2_rule'
  tag stig_id: 'GEN000120'
  tag gtitle: 'GEN000120'
  tag fix_id: 'F-38212r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001227']
  tag nist: ['SI-2 a']
end
