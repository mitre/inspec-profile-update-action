control 'SV-234848' do
  title 'SUSE operating system AppArmor tool must be configured to control whitelisted applications and user home directory access control.'
  desc %q(Using a whitelist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities.

The organization must identify authorized software programs and permit execution of authorized software by adding each authorized program to the "pam_apparmor" exception policy. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

Verification of whitelisted software occurs prior to execution or at system startup.

Users' home directories/folders may contain information of a sensitive nature. Nonprivileged users should coordinate any sharing of information with a System Administrator (SA) through shared resources.

AppArmor can confine users to their home directory, not allowing them to make any changes outside of their own home directories. Confining users to their home directory will minimize the risk of sharing information.

)
  desc 'check', 'Verify that the SUSE operating system AppArmor tool is configured to control whitelisted applications and user home directory access control.

Check that "pam_apparmor" is installed on the system with the following command:

> zypper info pam_apparmor | grep "Installed"

If the package "pam_apparmor" is not installed on the system, this is a finding.

Check that the "apparmor" daemon is running with the following command:

> systemctl status apparmor.service | grep -i active

Active: active (exited) since Fri 2017-01-13 01:01:01 GMT; 1day 1h ago

If something other than "Active: active" is returned, this is a finding.

Note: "pam_apparmor" must have properly configured profiles. All configurations will be based on the actual system setup and organization. See the "pam_apparmor" documentation for more information on configuring profiles.'
  desc 'fix', 'Configure the SUSE operating system to blacklist all applications by default and permit by whitelist.

Install "pam_apparmor" (if it is not installed) with the following command:

> sudo zypper in pam_apparmor

Enable/activate "Apparmor" (if it is not already active) with the following command:

> sudo systemctl enable apparmor.service

Start "Apparmor" with the following command:

> sudo systemctl start apparmor.service

Note: "pam_apparmor" must have properly configured profiles. All configurations will be based on the actual system setup and organization. See the "pam_apparmor" documentation for more information on configuring profiles.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38036r618813_chk'
  tag severity: 'medium'
  tag gid: 'V-234848'
  tag rid: 'SV-234848r622137_rule'
  tag stig_id: 'SLES-15-010390'
  tag gtitle: 'SRG-OS-000312-GPOS-00122'
  tag fix_id: 'F-37999r618814_fix'
  tag satisfies: ['SRG-OS-000312-GPOS-00122', 'SRG-OS-000312-GPOS-00123', 'SRG-OS-000312-GPOS-00124', 'SRG-OS-000324-GPOS-00125', 'SRG-OS-000326-GPOS-00126', 'SRG-OS-000368-GPOS-00154', 'SRG-OS-000370-GPOS-00155', 'SRG-OS-000480-GPOS-00230']
  tag 'documentable'
  tag cci: ['CCI-001764', 'CCI-001774', 'CCI-002165', 'CCI-002233', 'CCI-002235']
  tag nist: ['CM-7 (2)', 'CM-7 (5) (b)', 'AC-3 (4)', 'AC-6 (8)', 'AC-6 (10)']
end
