control 'SV-226915' do
  title 'Inetd or xinetd logging/tracing must be enabled.'
  desc 'Inetd or xinetd logging and tracing allows the system administrators to observe the IP addresses connecting to their machines and to observe what network services are being sought.  This provides valuable information when trying to find the source of malicious users and potential malicious users.'
  desc 'check', "Verify the default value of the inet service property tcp_trace.
# inetadm -p |grep tcp_trace

If the tcp_trace inet service property is not set or is set to FALSE, this is a finding.

Verify that all enabled inetd-managed processes have the tcp_trace inet service property set to the default value or TRUE.
# inetadm | grep enabled | awk '{print $NF}' | xargs inetadm -l | more

If any enabled inetd-managed processes have the tcp_trace inet service property set to FALSE, this is a finding."
  desc 'fix', "Enable logging or tracing for inetd.

Procedure:
# inetadm -M tcp_trace=TRUE

Set the tcp_trace inet service property to the default for all enabled inetd-managed services.

# inetadm | grep enabled | awk '{print $NF}' | xargs -I X inetadm -m X tcp_trace=

(Note:  The trailing '=' instructs inetd to use the default value for tcp_trace.)"
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36404r602815_chk'
  tag severity: 'low'
  tag gid: 'V-226915'
  tag rid: 'SV-226915r603265_rule'
  tag stig_id: 'GEN003800'
  tag gtitle: 'SRG-OS-000041'
  tag fix_id: 'F-36368r602816_fix'
  tag 'documentable'
  tag legacy: ['V-1011', 'SV-27430']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
