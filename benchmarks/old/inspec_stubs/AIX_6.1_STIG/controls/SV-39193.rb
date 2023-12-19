control 'SV-39193' do
  title 'Any active TFTP daemon must be authorized and approved in the system accreditation package.'
  desc 'TFTP is a file transfer protocol often used by embedded systems to obtain configuration data or software.    The service is unencrypted and does not require authentication of requests.  Data available using this service may be subject to unauthorized access or interception.'
  desc 'check', 'Determine if the TFTP daemon is active.
# grep -v "^#" /etc/inetd.conf |grep tftp
If TFTP is found enabled, it is a finding if it is not documented using site-defined procedures.'
  desc 'fix', 'Disable the TFTP daemon.
Edit /etc/inetd.conf and comment out the tftp line. 

Restart the inetd service.
# refresh -s inetd'
  impact 0.7
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38171r1_chk'
  tag severity: 'high'
  tag gid: 'V-4695'
  tag rid: 'SV-39193r1_rule'
  tag stig_id: 'GEN005140'
  tag gtitle: 'GEN005140'
  tag fix_id: 'F-33446r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'DCSW-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
