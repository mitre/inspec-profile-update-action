control 'SV-26887' do
  title 'The AppleTalk protocol must be disabled or not installed.'
  desc 'The AppleTalk suite of protocols is no longer in common use.  Binding this protocol to the network stack increases the attack surface of the host.  Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', %q(Verify the AppleTalk protocol handler is prevented from dynamic loading.
# grep 'install appletalk'  /etc/modprobe.conf /etc/modprobe.d/*
If anything is returned check that appletalk is disabled by having the executable set to  '/bin/true'. If an uncommented line containing "appletalk" is found which has not been disabled, this is a finding.)
  desc 'fix', 'Prevent the AppleTalk protocol handler for dynamic loading.
# echo "install appletalk /bin/true" >> /etc/modprobe.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-27846r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22524'
  tag rid: 'SV-26887r1_rule'
  tag stig_id: 'GEN007260'
  tag gtitle: 'GEN007260'
  tag fix_id: 'F-24130r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
