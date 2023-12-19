control 'SV-227867' do
  title 'Any active TFTP daemon must be authorized and approved in the system accreditation package.'
  desc 'TFTP is a file transfer protocol often used by embedded systems to obtain configuration data or software.    The service is unencrypted and does not require authentication of requests.  Data available using this service may be subject to unauthorized access or interception.'
  desc 'check', 'Determine if the TFTP daemon is active.
# svcs svc:/network/tftp/*
If TFTP is found enabled, it is a finding if it is not documented using site-defined procedures.'
  desc 'fix', 'Disable the TFTP daemon.
# svcadm disable svc:/network/tftp/*
# svcadm refresh inetd
If TFTP is found enabled, it is a finding if it is not documented.'
  impact 0.7
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30029r489997_chk'
  tag severity: 'high'
  tag gid: 'V-227867'
  tag rid: 'SV-227867r603266_rule'
  tag stig_id: 'GEN005140'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30017r489998_fix'
  tag 'documentable'
  tag legacy: ['V-4695', 'SV-28423']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
