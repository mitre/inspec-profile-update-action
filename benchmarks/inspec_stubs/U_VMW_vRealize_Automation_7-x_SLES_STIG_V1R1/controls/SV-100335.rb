control 'SV-100335' do
  title 'The SLES for vRealize must not have Teredo enabled.'
  desc 'Teredo is an IPv6 transition mechanism that involves tunneling IPv6 packets encapsulated in IPv4 packets. Unauthorized tunneling may circumvent network security.'
  desc 'check', 'Verify the Teredo service is not running:

ps ax | grep teredo | grep -v grep

If the Teredo process is running, this is a finding.'
  desc 'fix', 'Kill the Teredo service.

Edit startup scripts to prevent the service from running on startup. 

For Appliance OS, Teredo is not included by default, this is not a finding.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89377r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89685'
  tag rid: 'SV-100335r1_rule'
  tag stig_id: 'VRAU-SL-000665'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-96427r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
