control 'SV-254161' do
  title 'Nutanix AOS must generate audit records for all direct access to the information system.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'Confirm Nutanix AOS is configured with the ausearch tool. The ausearch tool is a feature of the audit rpm. 

$ sudo yum list installed audit
Installed Packages
audit.x86_64

If Installed Packages does not list the audit.x86_64 or No matching Packages to list is returned, this is a finding.'
  desc 'fix', 'Configure the system to generate audit records for all direct access to the information system by installing the audit package.

$ sudo yum install audit'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57646r846569_chk'
  tag severity: 'medium'
  tag gid: 'V-254161'
  tag rid: 'SV-254161r846571_rule'
  tag stig_id: 'NUTX-OS-000580'
  tag gtitle: 'SRG-OS-000472-GPOS-00217'
  tag fix_id: 'F-57597r846570_fix'
  tag satisfies: ['SRG-OS-000472-GPOS-00217', 'SRG-OS-000475-GPOS-00220']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
