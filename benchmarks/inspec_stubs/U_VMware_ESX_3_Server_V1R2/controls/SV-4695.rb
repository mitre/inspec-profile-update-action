control 'SV-4695' do
  title 'Any active TFTP daemon must be authorized and approved in the system accreditation package.'
  desc 'TFTP is a file transfer protocol often used by embedded systems to obtain configuration data or software.    The service is unencrypted and does not require authentication of requests.  Data available using this service may be subject to unauthorized access or interception.'
  desc 'check', 'Determine if the TFTP daemon is active.  If it is, this is a finding unless documented using site-defined procedures.'
  desc 'fix', 'Disable the TFTP daemon.'
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-716r2_chk'
  tag severity: 'high'
  tag gid: 'V-4695'
  tag rid: 'SV-4695r2_rule'
  tag stig_id: 'GEN005140'
  tag gtitle: 'GEN005140'
  tag fix_id: 'F-4623r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'DCSW-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
