control 'SV-248807' do
  title 'OL 8 audit tools must have a mode of "0755" or less permissive.'
  desc 'Protecting audit information includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information. 
 
OL 8 systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools, and the corresponding user rights, to make access decisions regarding the access to audit tools. 
 
Audit tools include but are not limited to vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Verify the audit tools are protected from unauthorized access, deletion, or modification by checking the permissive mode. 
 
Check the octal permission of each audit tool by running the following command: 
 
$ sudo stat -c "%a %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules 
 
755 /sbin/auditctl 
755 /sbin/aureport 
755 /sbin/ausearch 
750 /sbin/autrace 
755 /sbin/auditd 
755 /sbin/rsyslogd 
755 /sbin/augenrules 
 
If any of the audit tools has a mode more permissive than "0755", this is a finding.'
  desc 'fix', 'Configure the audit tools to be protected from unauthorized access by setting the correct permissive mode using the following command: 
 
$ sudo chmod 0755 [audit_tool] 
 
Replace "[audit_tool]" with the audit tool that does not have the correct permissive mode.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52241r779985_chk'
  tag severity: 'medium'
  tag gid: 'V-248807'
  tag rid: 'SV-248807r779987_rule'
  tag stig_id: 'OL08-00-030620'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-52195r779986_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
