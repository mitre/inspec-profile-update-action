control 'SV-248808' do
  title 'OL 8 audit tools must be owned by root.'
  desc 'Protecting audit information includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information. 
 
OL 8 systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools, and the corresponding user rights, to make access decisions regarding the access to audit tools. 
 
Audit tools include but are not limited to vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

'
  desc 'check', 'Verify the audit tools are owned by "root" to prevent any unauthorized access, deletion, or modification. 
 
Check the owner of each audit tool by running the following command: 
 
$ sudo stat -c "%U %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules 
 
root /sbin/auditctl 
root /sbin/aureport 
root /sbin/ausearch 
root /sbin/autrace 
root /sbin/auditd 
root /sbin/rsyslogd 
root /sbin/augenrules 
 
If any of the audit tools are not owned by "root", this is a finding.'
  desc 'fix', 'Configure the audit tools to be owned by "root" by running the following command: 
 
$ sudo chown root [audit_tool] 
 
Replace "[audit_tool]" with each audit tool not owned by "root".'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52242r779988_chk'
  tag severity: 'medium'
  tag gid: 'V-248808'
  tag rid: 'SV-248808r779990_rule'
  tag stig_id: 'OL08-00-030630'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-52196r779989_fix'
  tag satisfies: ['SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag 'documentable'
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9', 'AU-9']
end
