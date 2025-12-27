control 'SV-221705' do
  title 'The Oracle Linux operating system must not have the ypserv package installed.'
  desc 'Removing the "ypserv" package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services.'
  desc 'check', 'The NIS service provides an unencrypted authentication service that does not provide for the confidentiality and integrity of user passwords or the remote session.

Check to see if the "ypserve" package is installed with the following command:

# yum list installed ypserv

If the "ypserv" package is installed, this is a finding.'
  desc 'fix', 'Configure the operating system to disable non-essential capabilities by removing the "ypserv" package from the system with the following command:

# yum remove ypserv'
  impact 0.7
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23420r419187_chk'
  tag severity: 'high'
  tag gid: 'V-221705'
  tag rid: 'SV-221705r603260_rule'
  tag stig_id: 'OL07-00-020010'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-23409r419188_fix'
  tag 'documentable'
  tag legacy: ['V-99149', 'SV-108253']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
