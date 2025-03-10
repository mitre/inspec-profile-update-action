control 'SV-217102' do
  title 'Vendor-packaged SUSE operating system security patches and updates must be installed and up to date.'
  desc 'Timely patching is critical for maintaining the operational availability, confidentiality, and integrity of information technology (IT) systems. However, failure to keep SUSE operating system and application software patched is a common mistake made by IT professionals. New patches are released frequently, and it is often difficult for even experienced System Administrators (SAs) to keep abreast of all the new patches. When new weaknesses in a SUSE operating system exist, patches are usually made available by the vendor to resolve the problems. If the most recent security patches and updates are not installed, unauthorized users may take advantage of weaknesses in the unpatched software. The lack of prompt attention to patching could result in a system compromise.'
  desc 'check', 'Verify the SUSE operating system security patches and updates are installed and up to date.

Note: Updates are required to be applied with a frequency determined by the site or Program Management Office (PMO).

Check for required SUSE operating system patches and updates with the following command:

# sudo zypper patch-check

0 patches needed (0 security patches)

If the patch repository data is corrupt check that the available package security updates have been installed on the system with the following command:

# cut -d "|" -f 1-4 -s --output-delimiter " | " /var/log/zypp/history | grep -v " radd "

2016-12-14 11:59:36 | install | libapparmor1-32bit | 2.8.0-2.4.1
2016-12-14 11:59:36 | install | pam_apparmor | 2.8.0-2.4.1
2016-12-14 11:59:36 | install | pam_apparmor-32bit | 2.8.0-2.4.1

If the SUSE operating system has not been patched within the site or PMO frequency, this is a finding.'
  desc 'fix', 'Install the applicable SUSE operating system patches available from SUSE by running the following command:

# sudo zypper patch'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18330r369462_chk'
  tag severity: 'medium'
  tag gid: 'V-217102'
  tag rid: 'SV-217102r603262_rule'
  tag stig_id: 'SLES-12-010010'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18328r369463_fix'
  tag 'documentable'
  tag legacy: ['V-77047', 'SV-91743']
  tag cci: ['CCI-001227']
  tag nist: ['SI-2 a']
end
