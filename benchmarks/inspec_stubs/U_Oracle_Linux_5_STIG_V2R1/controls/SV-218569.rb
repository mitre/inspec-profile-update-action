control 'SV-218569' do
  title 'Any active TFTP daemon must be authorized and approved in the system accreditation package.'
  desc 'TFTP is a file transfer protocol often used by embedded systems to obtain configuration data or software.    The service is unencrypted and does not require authentication of requests.  Data available using this service may be subject to unauthorized access or interception.'
  desc 'check', 'Determine if the TFTP daemon is active.
# chkconfig --list | grep tftp

If TFTP is found enabled ("on") and not documented using site-defined procedures, it is a finding.'
  desc 'fix', 'Document or Disable the TFTP daemon.

If the TFTP daemon is necessary on the system, document and justify its usage for approval from the IAO.

If the TFTP daemon is not necessary on the system, turn it off.

# chkconfig tftp off
# service xinetd restart'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20044r562798_chk'
  tag severity: 'high'
  tag gid: 'V-218569'
  tag rid: 'SV-218569r603259_rule'
  tag stig_id: 'GEN005140'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-20042r562799_fix'
  tag 'documentable'
  tag legacy: ['V-4695', 'SV-63167']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
