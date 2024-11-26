control 'SV-38720' do
  title 'The system must not have the sprayd service active.'
  desc 'The sprayd service is sometimes used for network and nfs troubleshooting.  The spray service can be used for both buffer overflow and Denial of Service attacks by saturating the network.  The sprayd daemon is an unnecessary service.'
  desc 'check', 'Check the /etc/inetd.conf file for active sprayd service.

# grep sprayd /etc/inetd.conf | grep -v \\#

If the sprayd service is enabled,  this is a finding.'
  desc 'fix', 'Edit the /etc/inetd.conf file and comment out the sprayd service line. 

Restart the inetd service.   

# refresh -s inetd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37816r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29516'
  tag rid: 'SV-38720r1_rule'
  tag stig_id: 'GEN009320'
  tag gtitle: 'GEN009320'
  tag fix_id: 'F-33074r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
