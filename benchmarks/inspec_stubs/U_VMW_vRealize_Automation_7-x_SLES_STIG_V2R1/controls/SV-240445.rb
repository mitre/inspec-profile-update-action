control 'SV-240445' do
  title 'The SMTP service must not use .forward files.'
  desc 'The .forward file allows users to automatically forward mail to another system. Use of .forward files could allow the unauthorized forwarding of mail and could potentially create mail loops, which could degrade system performance.'
  desc 'check', 'Check if forwarding from sendmail:

# grep "0 ForwardPath" /etc/sendmail.cf

If the entry contains a file path and is not commented out, this is a finding.'
  desc 'fix', 'Disable forwarding for sendmail and remove ".forward" files from the system:

Remove all .forward files on the system:

# find / -name .forward -delete

Use the following command to disable forwarding:

# sed -i "s/O ForwardPath/#O ForwardPath/" /etc/sendmail.cf

Restart the sendmail service:

# service sendmail restart'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43678r671074_chk'
  tag severity: 'medium'
  tag gid: 'V-240445'
  tag rid: 'SV-240445r671076_rule'
  tag stig_id: 'VRAU-SL-000620'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-43637r671075_fix'
  tag 'documentable'
  tag legacy: ['SV-100317', 'V-89667']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
