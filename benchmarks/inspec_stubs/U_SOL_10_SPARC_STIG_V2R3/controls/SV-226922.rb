control 'SV-226922' do
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
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29084r485062_chk'
  tag severity: 'low'
  tag gid: 'V-226922'
  tag rid: 'SV-226922r603265_rule'
  tag stig_id: 'GEN003860'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29072r485063_fix'
  tag 'documentable'
  tag legacy: ['SV-27441', 'V-4701']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
