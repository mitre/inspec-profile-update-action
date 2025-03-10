control 'SV-221883' do
  title 'The Oracle Linux operating system must be configured to prevent unrestricted mail relaying.'
  desc 'If unrestricted mail relaying is permitted, unauthorized senders could use this host as a mail relay for the purpose of sending spam or other unauthorized activity.'
  desc 'check', 'Verify the system is configured to prevent unrestricted mail relaying.

Determine if "postfix" is installed with the following commands:

# yum list installed postfix
postfix-2.6.6-6.el7.x86_64.rpm 

If postfix is not installed, this is Not Applicable.

If postfix is installed, determine if it is configured to reject connections from unknown or untrusted networks with the following command:

# postconf -n smtpd_client_restrictions
smtpd_client_restrictions = permit_mynetworks, reject

If the "smtpd_client_restrictions" parameter contains any entries other than "permit_mynetworks" and "reject", this is a finding.'
  desc 'fix', %q(If "postfix" is installed, modify the "/etc/postfix/main.cf" file to restrict client connections to the local network with the following command:

# postconf -e 'smtpd_client_restrictions = permit_mynetworks,reject')
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23598r419721_chk'
  tag severity: 'medium'
  tag gid: 'V-221883'
  tag rid: 'SV-221883r603260_rule'
  tag stig_id: 'OL07-00-040680'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23587r419722_fix'
  tag 'documentable'
  tag legacy: ['V-99505', 'SV-108609']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
