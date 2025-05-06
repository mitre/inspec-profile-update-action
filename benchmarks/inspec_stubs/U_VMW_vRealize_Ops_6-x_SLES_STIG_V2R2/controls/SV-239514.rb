control 'SV-239514' do
  title 'The ypserv package must not be installed.'
  desc 'Removing the "ypserv" package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services.'
  desc 'check', 'Check if "ypserv" package is installed:

# rpm -q ypserv

If there is a "ypserv" package listed, this is a finding.'
  desc 'fix', 'To remove the "ypserv" package use the following command:

rpm -e ypserv'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42747r661991_chk'
  tag severity: 'medium'
  tag gid: 'V-239514'
  tag rid: 'SV-239514r661993_rule'
  tag stig_id: 'VROM-SL-000465'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-42706r661992_fix'
  tag 'documentable'
  tag legacy: ['SV-99149', 'V-88499']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
