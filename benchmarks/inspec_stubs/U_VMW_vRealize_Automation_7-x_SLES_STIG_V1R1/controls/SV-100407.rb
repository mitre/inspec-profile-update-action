control 'SV-100407' do
  title 'The SLES for vRealize must protect audit tools from unauthorized modification.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user has in order to make access decisions regarding the modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', "The following command will list which audit files on the system where the group-ownership has been modified:

# rpm -V audit | grep '^......G'

If there is output, this is a finding."
  desc 'fix', 'Run the following command to reset audit permissions to the correct values:

sudo rpm --setperms audit-1.8-0.34.26'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89449r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89757'
  tag rid: 'SV-100407r1_rule'
  tag stig_id: 'VRAU-SL-000910'
  tag gtitle: 'SRG-OS-000257-GPOS-00098'
  tag fix_id: 'F-96499r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
