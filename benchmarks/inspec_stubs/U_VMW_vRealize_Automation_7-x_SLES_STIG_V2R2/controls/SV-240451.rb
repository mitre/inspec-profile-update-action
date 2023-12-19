control 'SV-240451' do
  title 'The DECnet protocol must be disabled or not installed.'
  desc 'The DECnet suite of protocols is no longer in common use. Binding this protocol to the network stack increases the attack surface of the host. Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'Check that the DECnet protocol handler is prevented from dynamic loading:

# grep "install decnet /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*

If no result is returned, this is a finding.'
  desc 'fix', 'Prevent the DECnet protocol handler for dynamic loading:

# echo "install decnet /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43684r671092_chk'
  tag severity: 'medium'
  tag gid: 'V-240451'
  tag rid: 'SV-240451r671094_rule'
  tag stig_id: 'VRAU-SL-000650'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-43643r671093_fix'
  tag 'documentable'
  tag legacy: ['SV-100329', 'V-89679']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
