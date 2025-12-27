control 'SV-99217' do
  title 'The SLES for vRealize must not have Teredo enabled.'
  desc 'Teredo is an IPv6 transition mechanism that involves tunneling IPv6 packets encapsulated in IPv4 packets. Unauthorized tunneling may circumvent network security.'
  desc 'check', 'Verify the "Miredo" service is not running:

# ps ax | grep miredo | grep -v grep

If the Miredo process is running, this is a finding. 

Note: For Appliance OS, "Miredo" is not included by default, this is not a finding.'
  desc 'fix', 'Kill the "Miredo" service.

Edit startup scripts to prevent the service from running on startup.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88259r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88567'
  tag rid: 'SV-99217r1_rule'
  tag stig_id: 'VROM-SL-000645'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-95309r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
