control 'SV-254232' do
  title 'Nutanix AOS must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Any operating system providing too much information in error messages risks compromising the data and security of the structure, and content of error messages needs to be carefully considered by the organization.

Organizations carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, erroneous logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.'
  desc 'check', 'Verify Nutanix AOS has all system log files under the /home/log directory with a permission set to "640", by using the following command:

$ sudo find /home/log -perm /137 -type f -exec stat -c "%n %a" {} \\;

If command displays any output, this is a finding.'
  desc 'fix', %q(Configure the Nutanix AOS to set permissions of all log files under /home/log directory to "640" or more restricted, by using the following command:

$ sudo find /var/log -perm /137 -type f -exec chmod 640 '{}' \;)
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57717r846782_chk'
  tag severity: 'medium'
  tag gid: 'V-254232'
  tag rid: 'SV-254232r846784_rule'
  tag stig_id: 'NUTX-OS-001560'
  tag gtitle: 'SRG-OS-000205-GPOS-00083'
  tag fix_id: 'F-57668r846783_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
