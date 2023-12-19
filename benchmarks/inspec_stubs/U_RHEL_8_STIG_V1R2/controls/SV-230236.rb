control 'SV-230236' do
  title 'RHEL 8 operating systems must require authentication upon booting into emergency or rescue modes.'
  desc 'If the system does not require valid root authentication before it boots into emergency or rescue mode, anyone who invokes emergency or rescue mode is granted privileged access to all files on the system.'
  desc 'check', 'Check to see if the system requires authentication for rescue or emergency mode with the following command:

$ sudo grep sulogin-shell /usr/lib/systemd/system/rescue.service

ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue

If the "ExecStart" line is configured for anything other than "/usr/lib/systemd/systemd-sulogin-shell rescue", commented out, or missing, this is a finding.'
  desc 'fix', 'Configure the system to require authentication upon booting into emergency or rescue mode by adding the following line to the "/usr/lib/systemd/system/rescue.service" file.

ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-32905r567454_chk'
  tag severity: 'medium'
  tag gid: 'V-230236'
  tag rid: 'SV-230236r627750_rule'
  tag stig_id: 'RHEL-08-010151'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-32880r567455_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
