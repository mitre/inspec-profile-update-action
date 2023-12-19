control 'SV-253111' do
  title 'TOSS must be configured to prevent unrestricted mail relaying.'
  desc 'If unrestricted mail relaying is permitted, unauthorized senders could use this host as a mail relay for the purpose of sending spam or other unauthorized activity.'
  desc 'check', 'Verify the system is configured to prevent unrestricted mail relaying.

Determine if "postfix" is installed with the following commands:

$ sudo yum list installed postfix

postfix.x86_64  2:3.5.8-2.el8 

If postfix is not installed, this is Not Applicable.

If postfix is installed, determine if it is configured to reject connections from unknown or untrusted networks with the following command:

$ sudo postconf -n smtpd_client_restrictions

smtpd_client_restrictions = permit_mynetworks, reject

If the "smtpd_client_restrictions" parameter contains any entries other than "permit_mynetworks" and "reject", this is a finding.'
  desc 'fix', %q(If "postfix" is installed, modify the "/etc/postfix/main.cf" file to restrict client connections to the local network with the following command:

$ sudo postconf -e 'smtpd_client_restrictions = permit_mynetworks,reject')
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56564r825003_chk'
  tag severity: 'medium'
  tag gid: 'V-253111'
  tag rid: 'SV-253111r825005_rule'
  tag stig_id: 'TOSS-04-040700'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56514r825004_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
