control 'SV-239545' do
  title 'The DECnet protocol must be disabled or not installed.'
  desc 'The DECnet suite of protocols is no longer in common use. Binding this protocol to the network stack increases the attack surface of the host. Unprivileged local processes may be able to cause SLES for vRealize to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'Check that the "DECnet" protocol handler is prevented from dynamic loading:

# grep "install decnet /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*

If no result is returned, this is a finding.'
  desc 'fix', 'Prevent the "DECnet" protocol handler from dynamic loading:

# echo "install decnet /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42778r662084_chk'
  tag severity: 'medium'
  tag gid: 'V-239545'
  tag rid: 'SV-239545r662086_rule'
  tag stig_id: 'VROM-SL-000630'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-42737r662085_fix'
  tag 'documentable'
  tag legacy: ['SV-99211', 'V-88561']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
