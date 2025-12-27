control 'SV-206767' do
  title 'The Voice Video Endpoint must prevent unauthorized and unintended information transfer via shared system resources.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection. 

Unified capability (UC) and videoconferencing (VC) vendors have included capabilities in products that must be disabled for users. Many current UC and VC products include hooks into email, IM, and local file transfer. Peer networking options allowing transfer often use holding storage locations that are accessible to all users. This would allow potentially sensitive information to be shared without central control.'
  desc 'check', 'Verify the Voice Video Endpoint prevents unauthorized and unintended information transfer via shared system resources.

If the Voice Video Endpoint does not prevent unauthorized and unintended information transfer via shared system resources, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint to prevent unauthorized and unintended information transfer via shared system resources.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7023r363824_chk'
  tag severity: 'medium'
  tag gid: 'V-206767'
  tag rid: 'SV-206767r604140_rule'
  tag stig_id: 'SRG-NET-000190-VVEP-00044'
  tag gtitle: 'SRG-NET-000190'
  tag fix_id: 'F-7023r363825_fix'
  tag 'documentable'
  tag legacy: ['SV-81259', 'V-66769']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
