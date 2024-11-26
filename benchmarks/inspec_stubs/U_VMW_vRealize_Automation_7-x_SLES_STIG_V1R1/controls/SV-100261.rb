control 'SV-100261' do
  title 'The ypserv package must not be installed.'
  desc 'Removing the "ypserv" package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services.'
  desc 'check', 'Check if "ypserv" is installed:

# rpm -q ypserv

If there is a "ypserv" package listed, this is a finding.'
  desc 'fix', 'To remove the "telnet-server" package use the following command:

rpm -e ypserv'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89303r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89611'
  tag rid: 'SV-100261r1_rule'
  tag stig_id: 'VRAU-SL-000470'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-96353r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
