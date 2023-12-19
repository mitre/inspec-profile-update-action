control 'SV-218189' do
  title 'System security patches and updates must be installed and up-to-date.'
  desc 'Timely patching is critical for maintaining the operational availability, confidentiality, and integrity of information technology (IT) systems. However, failure to keep operating system and application software patched is a common mistake made by IT professionals. New patches are released daily, and it is often difficult for even experienced system administrators to keep abreast of all the new patches. When new weaknesses in an operating system exist, patches are usually made available by the vendor to resolve the problems. If the most recent security patches and updates are not installed, unauthorized users may take advantage of weaknesses present in the unpatched software. The lack of prompt attention to patching could result in a system compromise.'
  desc 'check', 'Obtain the list of available package security updates from the operating system vendor. Check the available package security updates have been installed on the system.

Use the "rpm" command to list the packages installed on the system.
Example:
# rpm -qa -last

If updated packages are available and applicable to the system and have not been installed, this is a finding.

For more information, see: (1) http://linux.oracle.com/errata/  and (2) http://linux.oracle.com/cve/.'
  desc 'fix', 'Install the patches or updated packages available from the vendor.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19664r561404_chk'
  tag severity: 'medium'
  tag gid: 'V-218189'
  tag rid: 'SV-218189r603259_rule'
  tag stig_id: 'GEN000120'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19662r561405_fix'
  tag 'documentable'
  tag legacy: ['V-783', 'SV-63099']
  tag cci: ['CCI-000366', 'CCI-001227']
  tag nist: ['CM-6 b', 'SI-2 a']
end
