control 'SV-215393' do
  title 'If Stream Control Transmission Protocol (SCTP) must be disabled on AIX.'
  desc 'The Stream Control Transmission Protocol (SCTP) is an IETF-standardized transport layer protocol. This protocol is not yet widely used. Binding this protocol to the network stack increases the attack surface of the host. Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'Check the system to determine if SCTP is installed: 

# lslpp -L bos.net.sctp
Fileset                      Level  State  Type  Description (Uninstaller)
  ----------------------------------------------------------------------------
lslpp: 0504-132  Fileset bos.net.sctp not installed.

If the "bos.net.sctp" fileset is not listed, SCTP is not installed, this is not a finding. 

If the "bos.net.sctp" fileset is listed then SCTP is installed, this is a finding.'
  desc 'fix', 'If SCTP is installed, unload it from the kernel and uninstall it from the system using the following commands: 
# sctpctrl unload
# installp -ug bos.net.sctp'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16591r294630_chk'
  tag severity: 'medium'
  tag gid: 'V-215393'
  tag rid: 'SV-215393r508663_rule'
  tag stig_id: 'AIX7-00-003088'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-16589r294631_fix'
  tag 'documentable'
  tag legacy: ['SV-101515', 'V-91417']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
