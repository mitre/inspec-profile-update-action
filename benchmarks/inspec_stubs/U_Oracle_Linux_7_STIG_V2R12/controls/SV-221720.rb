control 'SV-221720' do
  title 'The Oracle Linux operating system security patches and updates must be installed and up to date.'
  desc 'Timely patching is critical for maintaining the operational availability, confidentiality, and integrity of information technology (IT) systems. However, failure to keep operating system and application software patched is a common mistake made by IT professionals. New patches are released daily, and it is often difficult for even experienced System Administrators to keep abreast of all the new patches. When new weaknesses in an operating system exist, patches are usually made available by the vendor to resolve the problems. If the most recent security patches and updates are not installed, unauthorized users may take advantage of weaknesses in the unpatched software. The lack of prompt attention to patching could result in a system compromise.'
  desc 'check', 'Verify the operating system security patches and updates are installed and up to date. Updates are required to be applied with a frequency determined by the site or Program Management Office (PMO). 

Obtain the list of available package security updates from Oracle. The URL for updates is https://linux.oracle.com/errata/. It is important to note that updates provided by Oracle may not be present on the system if the underlying packages are not installed.

Check that the available package security updates have been installed on the system with the following command:

# yum history list | more
Loaded plugins: langpacks, product-id, subscription-manager
ID | Command line | Date and time | Action(s) | Altered
-------------------------------------------------------------------------------
70 | install aide | 2016-05-05 10:58 | Install | 1 
69 | update -y | 2016-05-04 14:34 | Update | 18 EE
68 | install vlc | 2016-04-21 17:12 | Install | 21 
67 | update -y | 2016-04-21 17:04 | Update | 7 EE
66 | update -y | 2016-04-15 16:47 | E, I, U | 84 EE

If package updates have not been performed on the system within the timeframe required by the site/program documentation, this is a finding. 

Typical update frequency may be overridden by Information Assurance Vulnerability Alert (IAVA) notifications from CYBERCOM.

If the operating system is in non-compliance with the Information Assurance Vulnerability Management (IAVM) process, this is a finding.'
  desc 'fix', 'Install the operating system patches or updated packages available from Oracle within 30 days or sooner as local policy dictates.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23435r419232_chk'
  tag severity: 'medium'
  tag gid: 'V-221720'
  tag rid: 'SV-221720r603260_rule'
  tag stig_id: 'OL07-00-020260'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23424r419233_fix'
  tag 'documentable'
  tag legacy: ['SV-108281', 'V-99177']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
