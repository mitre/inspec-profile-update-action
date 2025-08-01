control 'SV-223956' do
  title 'CA-TSS DOWN Control Option values must be properly specified.'
  desc 'Failure to a known safe state helps prevent systems from failing to a state that may cause loss of data or unauthorized access to system resources. Operating systems that fail suddenly and with no incorporated failure state planning may leave the system available but with a reduced security protection capability. Preserving operating system state information also facilitates system restart and return to the operational mode of the organization with less disruption to mission-essential processes. 

Abort refers to stopping a program or function before it has finished naturally. The term abort refers to both requested and unexpected terminations.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If only systems personnel are defined in SYS1.UADS and the DOWN Control Option values are set to DOWN(BW,SB,TN,OW), this is not a finding.

If non-systems personnel are defined in SYS1.UADS and the DOWN Control Option values are set to DOWN(BW,SB,TW,OW), this is not a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option setting as specified below and proceed with the change.

Setting if ONLY systems personnel are defined in SYS1.UADS: DOWN(BW,SB,TN,OW)

Setting if any non-systems personnel are defined in SYS1.UADS: DOWN(BW,SB,TW,OW)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25629r516267_chk'
  tag severity: 'medium'
  tag gid: 'V-223956'
  tag rid: 'SV-223956r561402_rule'
  tag stig_id: 'TSS0-ES-000830'
  tag gtitle: 'SRG-OS-000184-GPOS-00078'
  tag fix_id: 'F-25617r516268_fix'
  tag 'documentable'
  tag legacy: ['V-98619', 'SV-107723']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
