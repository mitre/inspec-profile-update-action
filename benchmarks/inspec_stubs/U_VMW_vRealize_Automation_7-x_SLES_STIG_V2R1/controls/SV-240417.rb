control 'SV-240417' do
  title 'The ypserv package must not be installed.'
  desc 'Removing the "ypserv" package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services.'
  desc 'check', 'Check if "ypserv" is installed:

# rpm -q ypserv

If there is a "ypserv" package listed, this is a finding.'
  desc 'fix', 'To remove the "telnet-server" package use the following command:

rpm -e ypserv'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43650r670990_chk'
  tag severity: 'medium'
  tag gid: 'V-240417'
  tag rid: 'SV-240417r670992_rule'
  tag stig_id: 'VRAU-SL-000470'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-43609r670991_fix'
  tag 'documentable'
  tag legacy: ['SV-100261', 'V-89611']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
