control 'SV-218678' do
  title 'The AppleTalk protocol must be disabled or not installed.'
  desc 'The AppleTalk suite of protocols is no longer in common use.  Binding this protocol to the network stack increases the attack surface of the host.  Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', %q(Verify the AppleTalk protocol handler is prevented from dynamic loading.
# grep 'install appletalk'  /etc/modprobe.conf /etc/modprobe.d/*
If anything is returned check that appletalk is disabled by having the executable set to  '/bin/true'. If an uncommented line containing "appletalk" is found which has not been disabled, this is a finding.)
  desc 'fix', 'Prevent the AppleTalk protocol handler for dynamic loading.
# echo "install appletalk /bin/true" >> /etc/modprobe.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20153r556448_chk'
  tag severity: 'medium'
  tag gid: 'V-218678'
  tag rid: 'SV-218678r603259_rule'
  tag stig_id: 'GEN007260'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-20151r556449_fix'
  tag 'documentable'
  tag legacy: ['V-22524', 'SV-63453']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
