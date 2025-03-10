control 'SV-100291' do
  title 'Mail relaying must be restricted.'
  desc 'If unrestricted mail relaying is permitted, unauthorized senders could use this host as a mail relay for the purpose of sending spam or other unauthorized activity.'
  desc 'check', 'Determine if Sendmail only binds to loopback addresses by examining the "DaemonPortOptions" configuration options.

# grep -i "O DaemonPortOptions" /etc/sendmail.cf

If there are uncommented DaemonPortOptions lines, and all such lines specify system loopback addresses, this is not a finding.

Otherwise, determine if Sendmail is configured to allow open relay operation.

# grep -i promiscuous_relay /etc/mail/sendmail.mc

If the promiscuous relay feature is enabled, this is a finding.'
  desc 'fix', 'If the SLES for vRealize does not need to receive mail from external hosts, add one or more "DaemonPortOptions" lines referencing system loopback addresses (such as "O DaemonPortOptions=Addr=127.0.0.1,Port=smtp,Name=MTA") and remove lines containing non-loopback addresses.

# sed -i "s/O DaemonPortOptions=Name=MTA/O DaemonPortOptions=Addr=127.0.0.1,Port=smtp,Name=MTA/" /etc/sendmail.cf

Restart the sendmail service:

# service sendmail restart'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89333r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89641'
  tag rid: 'SV-100291r1_rule'
  tag stig_id: 'VRAU-SL-000555'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-96383r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
