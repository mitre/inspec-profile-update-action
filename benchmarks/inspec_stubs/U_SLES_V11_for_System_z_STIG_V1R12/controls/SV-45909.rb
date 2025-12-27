control 'SV-45909' do
  title 'Any active TFTP daemon must be authorized and approved in the system accreditation package.'
  desc 'TFTP is a file transfer protocol often used by embedded systems to obtain configuration data or software.    The service is unencrypted and does not require authentication of requests.  Data available using this service may be subject to unauthorized access or interception.'
  desc 'check', 'Determine if the TFTP daemon is active.
# chkconfig --list | grep tftp

Or
# chkconfig tftp

If TFTP is found enabled and not documented using site-defined procedures, it is a finding.'
  desc 'fix', 'Document or Disable the TFTP daemon.

If the TFTP daemon is necessary on the system, document and justify its usage for approval from the IAO.

If the TFTP daemon is not necessary on the system, turn it off.

# chkconfig tftp off
# service xinetd restart'
  impact 0.7
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43217r1_chk'
  tag severity: 'high'
  tag gid: 'V-4695'
  tag rid: 'SV-45909r1_rule'
  tag stig_id: 'GEN005140'
  tag gtitle: 'GEN005140'
  tag fix_id: 'F-39288r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
