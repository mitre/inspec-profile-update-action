control 'SV-99147' do
  title 'The rsh-server package must not be installed.'
  desc %q(The "rsh-server" package provides several obsolete and insecure network services. Removing it decreases the risk of those services' accidental (or intentional) activation.)
  desc 'check', 'Check if "rsh-server" package is installed:

# rpm -q rsh-server

If there is a "rsh-server" package listed, this is a finding.'
  desc 'fix', 'To remove the "telnet-server" package use the following command:

rpm -e rsh-server'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88189r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88497'
  tag rid: 'SV-99147r1_rule'
  tag stig_id: 'VROM-SL-000460'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-95239r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
