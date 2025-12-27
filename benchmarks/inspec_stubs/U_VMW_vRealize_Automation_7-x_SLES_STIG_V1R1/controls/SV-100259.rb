control 'SV-100259' do
  title 'The rsh-server package must not be installed.'
  desc 'The "rsh-server" package provides several obsolete and insecure network services. Removing it decreases the risk of accidental (or intentional) activation of those services.'
  desc 'check', 'Check if "rsh-server" is installed:

# rpm -q rsh-server

If an "rsh-server" package is listed, this is a finding.'
  desc 'fix', 'To remove the "telnet-server" package, use the following command:

rpm -e rsh-server'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89301r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89609'
  tag rid: 'SV-100259r1_rule'
  tag stig_id: 'VRAU-SL-000465'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-96351r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
