control 'SV-216139' do
  title 'The system must disable ICMP redirect messages.'
  desc 'A malicious user can exploit the ability of the system to send ICMP redirects by continually sending packets to the system, forcing the system to respond with ICMP redirect messages, resulting in an adverse impact on the CPU performance of the system.'
  desc 'check', 'Determine the version of Solaris 11 in use.

# cat /etc/release

If the version of Solaris is earlier than Solaris 11.2, determine if ICMP redirect messages are disabled.

# ipadm show-prop -p _send_redirects -co current ipv4
# ipadm show-prop -p _send_redirects -co current ipv6

If the output of all commands is not "0", this is a finding.

If the version of Solaris is Solaris 11.2 or later, determine if ICMP redirect messages are disabled.

# ipadm show-prop -p send_redirects -co current ipv4
# ipadm show-prop -p send_redirects -co current ipv6

If the output of all commands is not "off", this is a finding.'
  desc 'fix', 'The Network Management profile is required.

If the version of Solaris is earlier than Solaris 11.2, disable send redirects for IPv4 and IPv6.

# pfexec ipadm set-prop -p _send_redirects=0 ipv4
# pfexec ipadm set-prop -p _send_redirects=0 ipv6 

If the version of Solaris is Solaris 11.2 or later, disable send redirects for IPv4 and IPv6.

# pfexec ipadm set-prop -p send_redirects=off ipv4
# pfexec ipadm set-prop -p send_redirects=off ipv6'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17377r372799_chk'
  tag severity: 'low'
  tag gid: 'V-216139'
  tag rid: 'SV-216139r603268_rule'
  tag stig_id: 'SOL-11.1-050090'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17375r372800_fix'
  tag 'documentable'
  tag legacy: ['SV-61069', 'V-48197']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
