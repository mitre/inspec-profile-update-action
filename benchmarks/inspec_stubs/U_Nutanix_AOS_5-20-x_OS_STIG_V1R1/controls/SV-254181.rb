control 'SV-254181' do
  title 'Nutanix AOS must provide the capability to centrally review and analyze audit records from multiple components within the system.'
  desc 'Successful incident response and auditing relies on timely, accurate system information and analysis to allow the organization to identify and respond to potential incidents in a proficient manner. If the operating system does not provide the ability to centrally review the operating system logs, forensic analysis is negatively impacted.

Segregation of logging data to multiple disparate computer systems is counterproductive and makes log analysis and log event alarming difficult to implement and manage, particularly when the system has multiple logging components writing to different locations or systems.

To support the centralized capability, the operating system must be able to provide the information in a format that can be extracted and used, allowing the application performing the centralization of the log records to meet this requirement.

'
  desc 'check', 'Confirm Nutanix AOS is configured with the ausearch tool. The ausearch tool is a feature of the audit rpm. 

$ sudo yum list installed audit
Installed Packages
audit.x86_64

If Installed Packages does not list the audit.x86_64 or No matching Packages to list is returned, this is a finding.'
  desc 'fix', 'Configure the system to provide on-demand (i.e., ad hoc ) audit report generation by installing the correct audit.x86_64 rpm.

$ sudo yum install audit'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57666r846629_chk'
  tag severity: 'medium'
  tag gid: 'V-254181'
  tag rid: 'SV-254181r846631_rule'
  tag stig_id: 'NUTX-OS-000790'
  tag gtitle: 'SRG-OS-000051-GPOS-00024'
  tag fix_id: 'F-57617r846630_fix'
  tag satisfies: ['SRG-OS-000051-GPOS-00024', 'SRG-OS-000054-GPOS-00025', 'SRG-OS-000122-GPOS-00063', 'SRG-OS-000348-GPOS-00136', 'SRG-OS-000349-GPOS-00137', 'SRG-OS-000350-GPOS-00138', 'SRG-OS-000351-GPOS-00139', 'SRG-OS-000352-GPOS-00140', 'SRG-OS-000353-GPOS-00141', 'SRG-OS-000354-GPOS-00142']
  tag 'documentable'
  tag cci: ['CCI-000154', 'CCI-000158', 'CCI-001875', 'CCI-001876', 'CCI-001877', 'CCI-001878', 'CCI-001879', 'CCI-001880', 'CCI-001881', 'CCI-001882']
  tag nist: ['AU-6 (4)', 'AU-7 (1)', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 b', 'AU-7 b']
end
