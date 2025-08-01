control 'SV-37514' do
  title 'Mail relaying must be restricted.'
  desc 'If unrestricted mail relaying is permitted, unauthorized senders could use this host as a mail relay for the purpose of sending SPAM or other unauthorized activity.'
  desc 'fix', %q(If the system uses sendmail, edit the sendmail.mc file and remove the "promiscuous_relay" configuration. Rebuild the sendmail.cf file from the modified sendmail.mc and restart the service. If the system does not need to receive mail from external hosts, add one or more DaemonPortOptions lines referencing system loopback addresses (such as "O DaemonPortOptions=Addr=127.0.0.1,Port=smtp,Name=MTA") and remove lines containing non-loopback addresses. Restart the service.

If the system uses Postfix, edit the main.cf file and add or edit the "smtpd_client_restrictions" line to have contents "permit_mynetworks, reject" or a similarly restrictive rule. If the system does not need to receive mail from external hosts, add or edit the "inet_interfaces" line to have contents "loopback-only" or a set of loopback addresses for the system. Restart the service.

If the system is using other SMTP software, consult the software's documentation for procedures to restrict mail relaying.)
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-23952'
  tag rid: 'SV-37514r2_rule'
  tag stig_id: 'GEN004710'
  tag gtitle: 'GEN004710'
  tag fix_id: 'F-31424r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001305']
  tag nist: ['SI-8 a']
end
