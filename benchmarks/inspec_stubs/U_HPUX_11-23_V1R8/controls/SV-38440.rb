control 'SV-38440' do
  title 'Any active TFTP daemon must be authorized and approved in the system accreditation package.'
  desc 'TFTP is a file transfer protocol often used by embedded systems to obtain configuration data or software.    The service is unencrypted and does not require authentication of requests.  Data available using this service may be subject to unauthorized access or interception.'
  desc 'check', 'Determine if the TFTP daemon is active.
# grep -v "^#" /etc/inetd.conf |grep tftp

If TFTP is enabled, it is a finding if it is not documented by site-defined procedures.'
  desc 'fix', 'Disable the TFTP daemon.
Edit /etc/inetd.conf and comment out the tftp line. Restart the inetd service via the command:
# inetd -c'
  impact 0.7
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36597r1_chk'
  tag severity: 'high'
  tag gid: 'V-4695'
  tag rid: 'SV-38440r1_rule'
  tag stig_id: 'GEN005140'
  tag gtitle: 'GEN005140'
  tag fix_id: 'F-31963r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'DCSW-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
