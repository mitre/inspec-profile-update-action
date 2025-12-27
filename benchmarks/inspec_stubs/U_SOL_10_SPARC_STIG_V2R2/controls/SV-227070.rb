control 'SV-227070' do
  title 'The system must have IEEE 1394 (Firewire) disabled unless needed.'
  desc 'Firewire is a common computer peripheral interface.  Firewire devices may include storage devices that could be used to install malicious software on a system or exfiltrate data.'
  desc 'check', "If the system needs IEEE 1394 (Firewire), this is not applicable.
Check if the firewire module is not disabled.
# grep 'exclude: s1394' /etc/system
If no results are returned, this is a finding."
  desc 'fix', 'Disable the firewire module.

# echo "exclude: s1394" >> /etc/system

Reboot for the changes to take effect.'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29232r485588_chk'
  tag severity: 'low'
  tag gid: 'V-227070'
  tag rid: 'SV-227070r603265_rule'
  tag stig_id: 'GEN008500'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29220r485589_fix'
  tag 'documentable'
  tag legacy: ['V-22580', 'SV-26972']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
