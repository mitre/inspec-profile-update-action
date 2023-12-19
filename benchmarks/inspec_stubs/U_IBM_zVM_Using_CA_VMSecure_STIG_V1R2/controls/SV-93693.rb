control 'SV-93693' do
  title 'IBM z/VM must have access to an audit reduction tool that allows for central data review and analysis.'
  desc 'Audit reduction is a process that manipulates collected audit information and organizes such information in a summary format that is more meaningful to analysts. Audit reduction and report generation capabilities do not always emanate from the same information system or from the same organizational entities conducting auditing activities. Audit reduction capability can include, for example, modern data mining techniques with advanced data filters to identify anomalous behavior in audit records. Audit records may at times be voluminous. Without a reduction tool crucial information may be overlooked.'
  desc 'check', 'Ask the system administrator if there is an audit reduction tool available for use with IBM z/VM.

Determine if a process is established to route audit records to the tool.

If there is no audit tool available, this is a finding.

If a procedure for routing audit records to the tool is not documented and on file with the ISSM/ISSO, this is a finding.'
  desc 'fix', 'Develop a process for routing audit records to an audit reduction tool.

Document the process and file with the ISSM/ISSO.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78575r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78987'
  tag rid: 'SV-93693r1_rule'
  tag stig_id: 'IBMZ-VM-002400'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-85737r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
