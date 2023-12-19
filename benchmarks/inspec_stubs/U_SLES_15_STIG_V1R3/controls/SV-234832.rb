control 'SV-234832' do
  title 'The SUSE operating system must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Any operating system providing too much information in error messages risks compromising the data and security of the structure, and content of error messages needs to be carefully considered by the organization.

Organizations carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, erroneous logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.'
  desc 'check', 'Verify the SUSE operating system has all system log files under the /var/log directory with a permission set to 640, by using the following command:

> sudo find /var/log -perm /137 -type f -exec stat -c "%n %a" {} \\;

If command displays any output, this is a finding.'
  desc 'fix', "Configure the SUSE operating system to set permissions of all log files under /var/log directory to 640 or more restricted, by using the following command:

> sudo find /var/log -perm /137 -type f -exec chmod 640 '{}' \\;"
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38020r618765_chk'
  tag severity: 'medium'
  tag gid: 'V-234832'
  tag rid: 'SV-234832r622137_rule'
  tag stig_id: 'SLES-15-010340'
  tag gtitle: 'SRG-OS-000205-GPOS-00083'
  tag fix_id: 'F-37983r618766_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
