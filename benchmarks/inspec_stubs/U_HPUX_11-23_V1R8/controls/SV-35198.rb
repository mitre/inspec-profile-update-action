control 'SV-35198' do
  title 'The system must use an access control program.'
  desc 'Access control programs (such as TCP_WRAPPERS) provide the ability to enhance system security posture.'
  desc 'check', %q(Locate the inetd.conf file (normally located within the /etc directory).
# find /etc -type f -name inetd.conf

Determine if TCP_WRAPPERS is used. The following example demonstrates one possible single inetd.conf line first without and then with the service tcp wrapped.
telnet stream tcp6 nowait root /usr/sbin/telnetd telnetd 
telnet stream tcp6 nowait root /usr/sbin/tcpd telnetd 

# cat <path>/inetd.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' |grep -v "^#" | grep tcpd

If there are unwrapped active services listed, this is a finding.)
  desc 'fix', 'Edit /etc/inetd.conf and use tcpd to wrap active services.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35044r1_chk'
  tag severity: 'medium'
  tag gid: 'V-940'
  tag rid: 'SV-35198r1_rule'
  tag stig_id: 'GEN006580'
  tag gtitle: 'GEN006580'
  tag fix_id: 'F-30334r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'EBRU-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
