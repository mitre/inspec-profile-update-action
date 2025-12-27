control 'SV-258885' do
  title 'The Photon operating system must be configured so that the x86 Ctrl-Alt-Delete key sequence is disabled on the command line.'
  desc 'When the Ctrl-Alt-Del target is enabled, a locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of systems availability due to unintentional reboot.'
  desc 'check', 'At the command line, run the following command to verify the ctrl-alt-del target is disabled and masked:

# systemctl status ctrl-alt-del.target --no-pager

Example output:

ctrl-alt-del.target
                Loaded: masked (Reason: Unit ctrl-alt-del.target is masked.)
                Active: inactive (dead)

If the "ctrl-alt-del.target" is not "inactive" and "masked", this is a finding.'
  desc 'fix', 'At the command line, run the following commands:

# systemctl disable ctrl-alt-del.target
# systemctl mask ctrl-alt-del.target
# systemctl daemon-reload'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Photon OS 4.0'
  tag check_id: 'C-62625r933714_chk'
  tag severity: 'medium'
  tag gid: 'V-258885'
  tag rid: 'SV-258885r933716_rule'
  tag stig_id: 'PHTN-40-000222'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-62534r933715_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
