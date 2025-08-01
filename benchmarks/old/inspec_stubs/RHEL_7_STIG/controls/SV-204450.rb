control 'SV-204450' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that the Datagram Congestion Control Protocol (DCCP) kernel module is disabled unless required.'
  desc 'Disabling DCCP protects the system against exploitation of any flaws in the protocol implementation.'
  desc 'check', 'Verify the operating system disables the ability to load the DCCP kernel module.

# grep -r dccp /etc/modprobe.d/* | grep -i "/bin/true" | grep -v "^#"

install dccp /bin/true

If the command does not return any output, or the line is commented out, and use of DCCP is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Verify the operating system disables the ability to use the DCCP kernel module.

Check to see if the DCCP kernel module is disabled with the following command:

# grep -i dccp /etc/modprobe.d/* | grep -i "blacklist" | grep -v "^#"

blacklist dccp

If the command does not return any output or the output is not "blacklist dccp", and use of the dccp kernel module is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the operating system to disable the ability to use the DCCP kernel module.

Create a file under "/etc/modprobe.d" with the following command:

# touch /etc/modprobe.d/dccp.conf

Add the following line to the created file:

install dccp /bin/true

Ensure that the DCCP module is blacklisted: 

# vi /etc/modprobe.d/blacklist.conf

Add or update the line:

blacklist dccp'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4574r88542_chk'
  tag severity: 'medium'
  tag gid: 'V-204450'
  tag rid: 'SV-204450r603261_rule'
  tag stig_id: 'RHEL-07-020101'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag fix_id: 'F-4574r88543_fix'
  tag 'documentable'
  tag legacy: ['V-77821', 'SV-92517']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
