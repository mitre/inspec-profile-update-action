control 'SV-27060' do
  title 'System security patches and updates must be installed and up-to-date.'
  desc 'Timely patching is critical for maintaining the operational availability, confidentiality, and integrity of Information Technology (IT) systems. However, failure to keep operating system and application software patched is a common mistake made by IT professionals. New patches are released daily, and it is often difficult for even experienced system administrators to keep abreast of all the new patches. When new weaknesses in an operating system exist, patches are usually made available by the vendor to resolve the problems. If the most recent security patches and updates are not installed, unauthorized users may take advantage of weaknesses present in the unpatched software. The lack of prompt attention to patching could result in a system compromise.'
  desc 'check', 'Obtain the list of available security patches from IBM.
Verify the available patches and service packs have been installed on the system.
Check the currently running TL (Technology Levels and Service Packs).
#oslevel -s

Perform the following to obtain a list of installed patches.
# /usr/sbin/instfix -i

If there are security patches available and applicable for the system that have not been installed, this is a finding.'
  desc 'fix', "Use a web browser to access the vendor's support web site. Download the service packs and patches. Use SMIT to apply the updates.   

#smitty update_all"
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36595r2_chk'
  tag severity: 'medium'
  tag gid: 'V-783'
  tag rid: 'SV-27060r2_rule'
  tag stig_id: 'GEN000120'
  tag gtitle: 'GEN000120'
  tag fix_id: 'F-31604r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001227']
  tag nist: ['SI-2 a']
end
