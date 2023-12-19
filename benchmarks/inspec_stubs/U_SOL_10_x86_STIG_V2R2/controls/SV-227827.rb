control 'SV-227827' do
  title 'The system must not have the finger service active.'
  desc "The finger service provides information about the system's users to network clients.  This information could expose information that could be used in subsequent attacks."
  desc 'check', 'If the "SUNWrcmds" package, containing the finger service executable, is not installed, this is not applicable.

# svcs finger
If the finger service is not disabled, this is a finding.'
  desc 'fix', 'Disable the finger service and restart inetd.
Procedure:
# svcadm disable finger
# svcadm refresh inetd'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29989r489847_chk'
  tag severity: 'low'
  tag gid: 'V-227827'
  tag rid: 'SV-227827r603266_rule'
  tag stig_id: 'GEN003860'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29977r489848_fix'
  tag 'documentable'
  tag legacy: ['V-4701', 'SV-27441']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
