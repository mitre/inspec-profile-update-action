control 'SV-248541' do
  title 'OL 8 operating systems must require authentication upon booting into rescue mode.'
  desc 'If the system does not require valid root authentication before it boots into emergency or rescue mode, anyone who invokes emergency or rescue mode is granted privileged access to all files on the system.'
  desc 'check', 'Determine if the system requires authentication for rescue mode with the following command: 
 
$ sudo grep sulogin-shell /usr/lib/systemd/system/rescue.service 
 
ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue 
 
If the "ExecStart" line is configured for anything other than "/usr/lib/systemd/systemd-sulogin-shell rescue" or is commented out or missing, this is a finding.'
  desc 'fix', 'Configure the system to require authentication upon booting into rescue mode by adding the following line to the "/usr/lib/systemd/system/rescue.service" file: 
 
ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51975r779187_chk'
  tag severity: 'medium'
  tag gid: 'V-248541'
  tag rid: 'SV-248541r779189_rule'
  tag stig_id: 'OL08-00-010151'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-51929r779188_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
