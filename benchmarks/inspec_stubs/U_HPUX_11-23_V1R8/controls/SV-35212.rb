control 'SV-35212' do
  title 'The SSH client must be configured to only use the SSHv2 protocol.'
  desc 'SSHv1 is not a DoD-approved protocol and has many well-known vulnerability exploits. Exploits of the SSH client could provide access to the system with the privileges of the user running the client.'
  desc 'check', %q(Check the SSH client configuration for allowed protocol versions. Note that keywords are case-insensitive and arguments (args) are case-sensitive. 

keyword=Protocol
arg(s)=2

# cat /opt/ssh/etc/ssh_config | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v '^#' | grep -i "Protocol"

If Protocol 2,1 (the default) or Protocol 1 are defined on a line without a leading comment, this is a finding.)
  desc 'fix', 'Edit the client configuration file Protocol entry to look like:

Protocol 2'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36631r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22456'
  tag rid: 'SV-35212r1_rule'
  tag stig_id: 'GEN005501'
  tag gtitle: 'GEN005501'
  tag fix_id: 'F-31999r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
