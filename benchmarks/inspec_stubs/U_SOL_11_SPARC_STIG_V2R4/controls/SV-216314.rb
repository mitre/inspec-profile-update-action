control 'SV-216314' do
  title 'X Window System connections that are not required must be disabled.'
  desc "If unauthorized clients are permitted access to the X server, a user's X session may be compromised."
  desc 'check', 'Determine if the X Window system is running.

Procedure:
# ps -ef |grep X

Ask the SA if the X Window system is an operational requirement. If it is not, this is a finding.'
  desc 'fix', 'Disable the X Windows server on the system.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17550r371030_chk'
  tag severity: 'medium'
  tag gid: 'V-216314'
  tag rid: 'SV-216314r603267_rule'
  tag stig_id: 'SOL-11.1-020560'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17548r371031_fix'
  tag 'documentable'
  tag legacy: ['SV-75499', 'V-61031']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
