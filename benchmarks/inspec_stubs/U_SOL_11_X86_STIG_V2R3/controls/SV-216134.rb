control 'SV-216134' do
  title 'The system must not respond to ICMP broadcast netmask requests.'
  desc 'By determining the netmasks of various computers in your network, an attacker can better map your subnet structure and infer trust relationships.'
  desc 'check', 'Determine if the response to address mask broadcast is disabled.

# ipadm show-prop -p _respond_to_address_mask_broadcast -co current ip

If the output of this command is not "0", this is a finding.'
  desc 'fix', 'The Network Management profile is required.

Disable responses to address mask broadcast.

# pfexec ipadm set-prop -p _respond_to_address_mask_broadcast=0 ip'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17372r372784_chk'
  tag severity: 'low'
  tag gid: 'V-216134'
  tag rid: 'SV-216134r603268_rule'
  tag stig_id: 'SOL-11.1-050040'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17370r372785_fix'
  tag 'documentable'
  tag legacy: ['SV-61049', 'V-48177']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
